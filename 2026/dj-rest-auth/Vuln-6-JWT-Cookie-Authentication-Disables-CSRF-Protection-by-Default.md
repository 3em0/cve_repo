# Vuln-6: JWT Cookie Authentication Disables CSRF Protection by Default

**Project:** dj-rest-auth (https://github.com/iMerica/dj-rest-auth)
**Version:** 7.1.1 (commit `c0c9c23`)
**Date:** 2026-03-14
**Severity:** MEDIUM
**CWE:** CWE-352 - Cross-Site Request Forgery

---

## Affected Files

```text
dj_rest_auth/app_settings.py (lines 40-41)
dj_rest_auth/jwt_auth.py (lines 135-144)
```

## Root Cause

Both CSRF-related settings default to `False`:

## Vulnerable Code

```python
# app_settings.py:40-41
'JWT_AUTH_COOKIE_USE_CSRF': False,
'JWT_AUTH_COOKIE_ENFORCE_CSRF_ON_UNAUTHENTICATED': False,
```

In `JWTCookieAuthentication.authenticate()`, the CSRF check is gated behind these two flags:

```python
# jwt_auth.py:141-144
if api_settings.JWT_AUTH_COOKIE_ENFORCE_CSRF_ON_UNAUTHENTICATED:
    self.enforce_csrf(request)
elif raw_token is not None and api_settings.JWT_AUTH_COOKIE_USE_CSRF:
    self.enforce_csrf(request)
```

Since both conditions are `False`, CSRF validation never executes.

## Impact

When JWT tokens are stored in cookies (the recommended approach for browser-based SPAs), browsers automatically include them with every request. Without CSRF protection, an attacker can craft a malicious page that performs state-changing actions on behalf of the victim:

```html
<!-- Attacker's page - changes victim's password -->
<form action="https://target.com/api/auth/password/change/" method="POST">
  <input name="new_password1" value="hacked123">
  <input name="new_password2" value="hacked123">
</form>
<script>document.forms[0].submit()</script>
```

Combined with Vuln-1 (no old password required), this enables full account takeover via a single page visit.

## Recommended Fix

Enable CSRF protection by default when cookies are used:

```python
'JWT_AUTH_COOKIE_USE_CSRF': True,
```

---

## References

- [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
- [dj-rest-auth source repository](https://github.com/iMerica/dj-rest-auth)
