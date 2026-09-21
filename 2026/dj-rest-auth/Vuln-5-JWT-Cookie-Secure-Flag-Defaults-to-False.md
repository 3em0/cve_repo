# Vuln-5: JWT Cookie Secure Flag Defaults to False

**Project:** dj-rest-auth (https://github.com/iMerica/dj-rest-auth)
**Version:** 7.1.1 (commit `c0c9c23`)
**Date:** 2026-03-14
**Severity:** MEDIUM
**CWE:** CWE-614 - Sensitive Cookie in HTTPS Session Without 'Secure' Attribute

---

## Affected File

```text
dj_rest_auth/app_settings.py (line 35)
```

## Root Cause

```python
# app_settings.py:35
'JWT_AUTH_SECURE': False,
```

With this default, JWT cookies are transmitted over both HTTP and HTTPS. In any environment where HTTP traffic occurs (mixed-content pages, internal proxies, health check endpoints), the JWT token is exposed to network-level interception.

## Impact

An attacker performing a man-in-the-middle attack (e.g., on a shared Wi-Fi network, or via ARP spoofing on an internal network) can capture JWT tokens transmitted over unencrypted HTTP connections, leading to session hijacking.

## Recommended Fix

Default to `True` (secure-by-default):

```python
'JWT_AUTH_SECURE': True,
```

---

## References

- [CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)
- [dj-rest-auth source repository](https://github.com/iMerica/dj-rest-auth)
