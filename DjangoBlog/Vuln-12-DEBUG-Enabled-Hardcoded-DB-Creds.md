# Vuln-12: DEBUG Enabled by Default + Hardcoded Database Credentials

**Project:** DjangoBlog (https://github.com/liangliangyy/DjangoBlog)
**Version:** Latest master (commit `06f76ea`)
**Date:** 2026-03-14
**Severity:** LOW
**OWASP:** A05:2021 - Security Misconfiguration
**CWE:** CWE-798 - Use of Hard-coded Credentials

---

## Affected File

```
djangoblog/settings.py (lines 34, 109-120)
```

## Root Cause

`DEBUG` defaults to `True` and database credentials default to `root`/`root` when environment variables are not set:

```python
DEBUG = env_to_bool('DJANGO_DEBUG', True)

DATABASES = {
    'default': {
        'USER': os.environ.get('DJANGO_MYSQL_USER') or 'root',
        'PASSWORD': os.environ.get('DJANGO_MYSQL_PASSWORD') or 'root',
    }
}
```

## Impact

Deployments that omit environment variable configuration will expose detailed Django error pages (including stack traces, settings, and local variables) and use guessable database credentials.

## Recommended Fix

Set `DEBUG` default to `False`. Remove hardcoded database credential fallbacks; require environment variables.

---

## References

- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [Django Security Best Practices](https://docs.djangoproject.com/en/stable/topics/security/)
- DjangoBlog source: https://github.com/liangliangyy/DjangoBlog
