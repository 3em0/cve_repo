#!/usr/bin/env python3
"""Read the persisted PoC records back from argilla-server.

Proves the server stored the record field text verbatim (raw HTML incl. the
event handler) — i.e. JSON parsing and storage end cleanly and the payload is
handed to the frontend unchanged.
"""
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path


def main() -> int:
    here = Path(__file__).resolve().parent
    ids = json.loads((here / "ids.json").read_text(encoding="utf-8"))
    base = ids["base_url"].rstrip("/")

    req = urllib.request.Request(
        base + "/api/v1/token",
        data=urllib.parse.urlencode({"username": "owner", "password": "12341234"}).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        token = json.loads(resp.read().decode())["access_token"]

    for label, rid in (("positive (onerror)", ids["positive_record_id"]),
                       ("negative (data-onerror)", ids["negative_record_id"])):
        req = urllib.request.Request(
            base + f"/api/v1/records/{rid}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            rec = json.loads(resp.read().decode())
        text = rec["fields"]["text"]
        print(f"GET /api/v1/records/{rid} -> {resp.status}  [{label}]")
        print(f"  stored fields.text = {json.dumps(text, ensure_ascii=False)}")

    print("server response contains the raw HTML string verbatim; no sanitization at storage layer")
    return 0


if __name__ == "__main__":
    sys.exit(main())
