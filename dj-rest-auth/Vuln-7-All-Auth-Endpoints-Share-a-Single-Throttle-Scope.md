# Vuln-7: All Auth Endpoints Share a Single Throttle Scope

**Project:** dj-rest-auth (https://github.com/iMerica/dj-rest-auth)
**Version:** 7.1.1 (commit `c0c9c23`)
**Date:** 2026-03-14
**Severity:** LOW
**CWE:** CWE-799 - Improper Control of Interaction Frequency

---

## Affected File

```text
dj_rest_auth/views.py (lines 40, 139, 252, 278, 302)
```

## Root Cause

Every view in the package uses the same `throttle_scope`:

## Vulnerable Code

```python
# All views use:
throttle_scope = 'dj_rest_auth'
```

Affected views: `LoginView`, `LogoutView`, `PasswordResetView`, `PasswordResetConfirmView`, `PasswordChangeView`.

## Impact

1. **Cross-endpoint throttle exhaustion:** If a deployer configures `DEFAULT_THROTTLE_RATES['dj_rest_auth']`, an attacker can exhaust the shared quota by flooding a low-cost endpoint (e.g., password reset), thereby blocking the victim from logging in.
2. **No default rate limiting:** By default, `DEFAULT_THROTTLE_RATES` does not include a `dj_rest_auth` entry, so the login endpoint has zero brute-force protection out of the box.

## Recommended Fix

Use distinct throttle scopes per endpoint:

```python
class LoginView(GenericAPIView):
    throttle_scope = 'dj_rest_auth_login'

class PasswordResetView(GenericAPIView):
    throttle_scope = 'dj_rest_auth_password_reset'

# etc.
```

---

## References

- [CWE-799: Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)
- [dj-rest-auth source repository](https://github.com/iMerica/dj-rest-auth)
