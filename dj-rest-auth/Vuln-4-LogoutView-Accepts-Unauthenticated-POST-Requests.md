# Vuln-4: LogoutView Accepts Unauthenticated POST Requests

**Project:** dj-rest-auth (https://github.com/iMerica/dj-rest-auth)
**Version:** 7.1.1 (commit `c0c9c23`)
**Date:** 2026-03-14
**Severity:** MEDIUM
**CWE:** CWE-862 - Missing Authorization

---

## Affected File

```text
dj_rest_auth/views.py (lines 131-138)
```

## Root Cause

`LogoutView` uses `permission_classes = (AllowAny,)`, allowing anyone, including unauthenticated users, to send POST requests to the logout endpoint:

## Vulnerable Code

```python
# views.py:131-138
class LogoutView(APIView):
    permission_classes = (AllowAny,)
    ...
```

## Steps to Reproduce

```bash
# No authentication token needed
curl -s -X POST http://127.0.0.1:8000/api/auth/logout/
# Returns: {"detail":"Successfully logged out."} (HTTP 200)
```
![alt text](../dists/dj_rest_auth4.png)
## Impact

In JWT mode with `token_blacklist` enabled, an attacker who obtains a victim's refresh token can submit it to the unauthenticated logout endpoint to blacklist it, effectively performing a denial-of-service attack by invalidating the victim's session. The endpoint should require authentication so that only the token owner can revoke their own tokens.

## Recommended Fix

Change the permission class to `IsAuthenticated`:

```python
class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)
```

---

## References

- [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)
- [dj-rest-auth source repository](https://github.com/iMerica/dj-rest-auth)
