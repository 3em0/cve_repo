# Sony NNabla 1.39.0 — Code Injection in NNP Converter (`function.type` eval())

## Summary

Sony NNabla 1.39.0 is affected by a code injection in the NNP converter component. The converter concatenates the attacker-controlled `function.type` field of an NNP model file into Python `eval()` calls during the documented `nnabla_cli convert` command. A duplicate-network bypass lets the malicious `function.type` reach `eval()` even though the version gate inspects a benign copy of the same network, resulting in arbitrary command execution on the machine that converts the model. The injected command runs first; the process only crashes afterwards on an unrelated `KeyError`, which does not undo the execution.

## Affected Product

| Field | Value |
|---|---|
| Vendor | Sony (NNabla project) |
| Product | NNabla (Neural Network Libraries) |
| Affected versions | 1.39.0 (verified; official PyPI wheel, Build 240523014612; source pinned at commit `cbf0545bf36b5fa317d71e5f6110bb9827b7da98`, dated 2024-05-22). 1.39.0 is the final release (2024-05-29); the master branch still contains the vulnerable `eval()` calls as of 2026-09-24. Earliest affected version `[unknown]` |
| Component | `python/src/nnabla/utils/converter/utils.py` — `func_set_nnabla_version_decorate()` (lines 101-123), gate `func_set_import_nnp()` (lines 352-356) |
| Platform | Any platform running the Python package / `nnabla_cli` |
| Project status | EOL — development and security support ended per the official 2025-04-03 announcement; GitHub repository archived read-only on 2026-07-29 (API `"archived": true`); no upstream fix is expected |
| Vulnerability type | CWE-94: Code Injection |

## Root Cause

**Location:** `python/src/nnabla/utils/converter/utils.py:101-123` (`func_set_nnabla_version_decorate`; `eval()` at lines 111 and 116, post-execution `KeyError` at line 122), gate at `python/src/nnabla/utils/converter/utils.py:352-356` (`func_set_import_nnp`) — verified at commit `cbf0545bf36b5fa317d71e5f6110bb9827b7da98`. The `utils.py` shipped in the official PyPI wheel `nnabla==1.39.0` is byte-identical to this pinned source (sha256 `98de76215cf8c6a8ac714a82a883d98bd01112f784d666b3a839453351f78f6b`). The same `eval()` calls are still present on `master` (lines 111, 116, plus a related `eval` of the derived parameter name at line 136) as of 2026-09-24.

Two defects combine:

1. **The gate checks only the first same-name network.** NNP containers are protobuf messages; `text_format.Merge` keeps two `network` entries with the same `name` (the import phase even expands both — `Expanding shared.` appears twice in the capture). The version gate returns the function-type set of only the *first* matching network, so a benign duplicate passes the check while a malicious second copy does not:

```python
def func_set_import_nnp(nnp):
    network_name = nnp.protobuf.executor[0].network_name
    for _net in nnp.protobuf.network:
        if _net.name == network_name:
            return set([f.type for f in _net.function])   # only the FIRST match
```

2. **The decorator evals the type string of every same-name network.** Verified call chain (from the reproduction traceback): `nnabla_cli convert` → `utils/cli/cli.py:147` → `utils/cli/convert.py:111` (`convert_files`) → `utils/converter/commands.py:336` → `commands.py:145` (`_export_from_nnp`) → `func_set_nnabla_version_decorate(nnp, args.nnp_version)` → `utils.py:111`:

```python
for n in nnp.protobuf.network:            # iterates ALL same-name networks
    if n.name == network_name:
        exec_network = n
        for f in n.function:
            try:
                eval(f"f.{convert_from_camel_to_snake(f.type) +'_param'}")  # line 111
            except AttributeError:
                try:
                    eval(f"f.{f.type.lower() + '_param'}")                  # line 116
                except AttributeError:
                    no_param = True
            old_info = _nnabla_func_info_old[f.type]   # line 122: KeyError comes only later
```

**Payload mechanics.** The eval template is `f.<type>_param`, so the type string must place the injected command at a position that is *evaluated before* the trailing `_param` is parsed-then-evaluated. A naive payload such as `__class__ and 0 or __import__('os').system('cmd')` concatenates to `... system('cmd')_param`, which is a `SyntaxError` (call result juxtaposed with an identifier) and never executes. A working form ends the command with an attribute access — `__class__ and 0 or __import__('os').system('cmd').__class__` — so the appended suffix yields `... system('cmd').__class___param`, a legal attribute lookup. Evaluation then proceeds left to right: `f.__class__ and 0` is falsy, the `or` branch calls `os.system('cmd')` — the command executes — and only the subsequent attribute lookup on the integer result raises `AttributeError`, which the converter catches. Processing continues and dies at line 122 (`_nnabla_func_info_old[f.type]`) with `KeyError`, because the payload string is not a known function type. The executed command has already taken effect by then.

## Proof of Concept

### Prerequisites

- Python with the official `nnabla==1.39.0` package (PyPI) installed; `nnabla_cli` on PATH.
- The converter's per-version function table must be resolvable: `functions.yaml` for the target version either downloadable at run time or already cached at `~/.nnabla/function_info_1.39.0.yaml`. Without it, `convert` aborts earlier in `func_set_get_from_repo` with `ValueError: nnabla v1.39.0 does not exist?` **before** reaching the vulnerable code (observed during reproduction; recorded here as a real precondition, not part of the vulnerability).
- A crafted `malicious.nnp` file (the victim converts an attacker-supplied model — e.g. downloaded from a repository, model hub, or received in a collaboration workflow).

### Steps to Reproduce

1. Build `malicious.nnp`: a ZIP container (NNP format) produced with NNabla's own protobuf API (`make_poc.py` in the attached `poc/` directory), containing `nnp_version.txt` and `network.nntxt` with the structure shown under "Sanitized PoC input" — two `network` messages sharing the name `shared` (the first carrying only a benign `Identity` function, the second carrying the payload as `function.type`), and `executor[0].network_name` pointing at `shared`.

![malicious.nnp structure: archive listing and network.nntxt with duplicate network names and the payload function.type](screenshots/01-malicious-nnp-structure.png)

This screenshot shows the real archive listing and `network.nntxt`: both networks are named `shared`; only the second network's `function.type` carries the payload.

2. In a clean working directory, run the documented command:

```text
nnabla_cli convert malicious.nnp out_malicious.nnp --nnp-version 1.39.0
```

The import phase expands both same-name networks, then `func_set_nnabla_version_decorate` evaluates the second network's type string: the injected command executes and the canary file `pwn_canary.txt` appears; immediately afterwards the process exits 255 with `KeyError` at `utils.py:122`, whose key is the payload string itself.

![nnabla_cli convert on malicious.nnp: duplicate networks expanded, KeyError raised at utils.py:122 with the payload as key, exit 255](screenshots/02-convert-malicious-run.png)

This screenshot shows the real run: both `Expanding shared.` lines, the traceback through `commands.py:145` into `func_set_nnabla_version_decorate`, the `KeyError` carrying the payload as its key, and `[exit 255]`.

![canary file pwn_canary.txt exists (15 bytes) with content nnp-eval-canary, written by the injected command inside the real nnabla_cli process](screenshots/03-canary-landing.png)

This screenshot shows `ls -l pwn_canary.txt` (15 bytes) and `cat pwn_canary.txt` (`nnp-eval-canary`) — the command injected through `function.type` executed before the crash.

3. Negative control: rebuild the same file with the second network's `function.type` replaced by `Identity` (`control_identity.nnp`) and rerun the conversion. The file converts cleanly (exit 0, `out_control.nnp` written) and no canary appears — isolating the duplicate network's type string as the payload carrier.

![negative control converting cleanly with exit 0, out_control.nnp written, and no canary file](screenshots/04-negative-control.png)

This screenshot shows the negative control: `Converting: out_control.nnp successfully!`, `[exit 0]`, no `pwn_canary.txt`, and the output container present.

### Verification (two independent rounds, environments as they actually were)

- **Round 1 — reporter's original verification (Docker).** Ubuntu 22.04 container, official `pip` `nnabla==1.39.0`, runtime network disabled, image/artifact hashes pinned and checked. The malicious NNP made the real `nnabla_cli` process write a fixed-content canary; a benign NNP converted normally; repeated runs were deterministic (byte-identical `result.json`). The sample hashes of that round live in the reporter's environment and are not reproduced here.
- **Round 2 — reproduction for this report (WSL2, screenshots above).** WSL2 Ubuntu 24.04.3 (kernel `6.18.33.2-microsoft-standard-WSL2`), CPython 3.10.21 (uv-managed venv), official PyPI wheel `nnabla==1.39.0` (Build 240523014612), network available; `~/.nnabla/function_info_1.39.0.yaml` pre-fetched from the `v1.39.0` tag (sha256 `f3fca3c18e1c94b40648f7cb3d74435f2ca6f0cfef746414de1b920278e08b9a`). Installed `utils.py` sha256 equals the pinned commit's file (see Root Cause). Sample hashes of this round (`poc/SHA256SUMS.txt`): `malicious.nnp` `cc92c4cc7438965556c3915b945068490e9d51d6611961c7a1549e6acf3caa8e`, `control_identity.nnp` `bfe1e65b33d5959d9bdd81238aa10d59f2b3c40c6e9f16acd9ea25136b745082`. Both rounds were generated independently; structure and generation method are identical.

### Expected vs Actual

- Expected: the converter accepts only known function types; unknown/garbage `function.type` values are rejected before any processing; duplicate network names are rejected at parse time.
- Actual: a second same-name network bypasses the gate and its `function.type` is executed by `eval()` inside the real `nnabla_cli` process; the trailing attribute probe raises `AttributeError`, which the converter catches; the subsequent unknown-type lookup raises `KeyError` (`utils.py:122`) and the process exits 255 — after the injected command has already run.

### Sanitized PoC input

Structure of `network.nntxt` (abridged; generated by `poc/make_poc.py`):

```text
nnp_version.txt
    1.39.0

network.nntxt (protobuf text format, abridged)
    network {
      name: "shared"
      function { name: "f0"  type: "Identity"  input: "x0"  output: "x1" }
    }
    network {
      name: "shared"                                          # same name as first
      function {
        name: "f0"
        type: "__class__ and 0 or __import__('os').system('printf nnp-eval-canary > pwn_canary.txt').__class__"
        input: "x0"
        output: "x1"
      }
    }
    executor {
      name: "execution"
      network_name: "shared"
    }
```

The payload is all-lowercase because the converter first rewrites the type string with a camel-to-snake conversion, which would corrupt any uppercase letters before the `eval()`.

## Impact

- Confidentiality: High — arbitrary code execution allows full read access to files/secrets available to the converting user (including CI credentials).
- Integrity: High — arbitrary file modification is possible under the same privileges.
- Availability: High — arbitrary process termination or system interference is possible.
- Scope: code execution in the victim user's context; typical delivery is a malicious `.nnp` model shared via repositories, model hubs, or pipelines (model supply-chain attack on ML developer tooling).

## Attack Vector and Severity (CVSS v3.1)

| Metric | Value | Rationale |
|---|---|---|
| Attack Vector | Network (N) | The crafted model file is delivered remotely (download, repo, hub, CI artifact) |
| Attack Complexity | Low (L) | Exploitation is deterministic; no race or mitigation bypass needed |
| Privileges Required | None (N) | No privileges on the victim beyond getting the file converted |
| User Interaction | Required (R) | The victim must run the conversion on the attacker-supplied model |
| Scope | Unchanged (U) | Impact is within the converting user's security context |
| Confidentiality | High (H) | Arbitrary code execution |
| Integrity | High (H) | Arbitrary code execution |
| Availability | High (H) | Arbitrary code execution |

```text
Score: 8.8 (High)
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H
```

## Remediation

- Replace the `eval()`-based parameter probing in `func_set_nnabla_version_decorate` (`utils.py:101-123`) with safe attribute lookup on the protobuf object, e.g. `hasattr(f, candidate)` / `getattr(f, candidate, None)`, which never executes attacker-controlled code.
- Validate `function.type` against the set of known NNabla function types before any processing and fail with a clear error message on unknown types (this also removes the post-execution `KeyError` / exit-255 symptom).
- Enforce `network` name uniqueness when parsing NNP containers to close the gate-bypass class (`func_set_import_nnp`, `utils.py:352-356`).
- Apply the same fix to the related `eval()` of the derived parameter name at `utils.py:136` on `master`.
- Project status caveat: the project is EOL and the repository is archived, so an upstream fix is not expected. Until a patched fork exists, users must not convert `.nnp` files from untrusted sources with `nnabla_cli` or the converter API; maintainers of downstream distributions should patch the listed sites in their packaging.

## References

- Source repository: https://github.com/sony/nnabla (archived, read-only)
- Verified vulnerable source: https://github.com/sony/nnabla/blob/cbf0545bf36b5fa317d71e5f6110bb9827b7da98/python/src/nnabla/utils/converter/utils.py
- Final release: https://github.com/sony/nnabla/releases/tag/v1.39.0 (2024-05-29)
- Upstream report: `[pending — Sony HackerOne submission; the archived GitHub repository provides no issue tracker or private reporting channel]`
- CWE: https://cwe.mitre.org/data/definitions/94.html
- Vendor advisory: `[none]`


