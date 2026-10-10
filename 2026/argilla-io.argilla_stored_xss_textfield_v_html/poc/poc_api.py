#!/usr/bin/env python3
"""Set up the Argilla repro dataset via the REST API and persist the PoC records.

Flow (all calls real HTTP against a running argilla-server):
  1. login (POST /api/v1/oauth/token)               -> bearer token (never printed)
  2. create/find workspace
  3. create dataset (text field, use_markdown=false)
  4. bulk-create positive record (POST /api/v1/datasets/{id}/records/bulk)
  5. bulk-create negative record (same endpoint)
  6. publish dataset
  7. write ids.json with dataset/record ids + UI URL

Stdlib only (urllib), so it runs in any Python >= 3.9.
"""
import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def http(base: str, method: str, path: str, token=None, payload=None, form=None):
    url = base.rstrip("/") + path
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if form is not None:
        data = urllib.parse.urlencode(form).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.status, json.loads(body) if body.strip() else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(body) if body.strip() else {}
        except json.JSONDecodeError:
            return e.code, {"raw": body[:200]}


def print_step(label: str, status: int, extra: str = ""):
    print(f"{label:<58} -> {status} {extra}".rstrip())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://localhost:6900")
    ap.add_argument("--username", default="owner")
    ap.add_argument("--password", default="12341234")
    ap.add_argument("--workspace", default="seq097-ws")
    ap.add_argument("--dataset", default="seq097-dom-html-render")
    args = ap.parse_args()

    here = Path(__file__).resolve().parent
    pos_body = json.loads((here / "poc_positive.json").read_text(encoding="utf-8"))
    neg_body = json.loads((here / "poc_negative.json").read_text(encoding="utf-8"))

    base = args.base_url

    # 1. login
    status, body = http(base, "POST", "/api/v1/token",
                        form={"username": args.username, "password": args.password})
    print_step("POST /api/v1/token (login)", status)
    if status != 201:
        print(f"  login failed: {body}")
        return 1
    token = body["access_token"]

    # 2. workspace: create or find
    status, body = http(base, "POST", "/api/v1/workspaces", token,
                        payload={"name": args.workspace})
    if status == 201:
        ws_id = body["id"]
        print_step(f"POST /api/v1/workspaces ('{args.workspace}')", status)
    else:
        print_step(f"POST /api/v1/workspaces ('{args.workspace}')", status, "(already exists, looking up)")
        status, body = http(base, "GET", "/api/v1/me/workspaces", token)
        print_step("GET  /api/v1/me/workspaces", status)
        ws_id = next((w["id"] for w in body.get("items", []) if w["name"] == args.workspace), None)
        if not ws_id:
            print("  workspace not found")
            return 1

    # 3. dataset (draft), then add one plain text field (use_markdown=false) + a label question
    payload = {"name": args.dataset, "guidelines": "seq097 dom_html_render repro dataset",
               "workspace_id": ws_id}
    status, body = http(base, "POST", "/api/v1/datasets", token, payload=payload)
    print_step("POST /api/v1/datasets", status)
    if status == 409:
        status, body = http(base, "GET", "/api/v1/me/datasets", token)
        print_step("GET  /api/v1/me/datasets (dataset already exists)", status)
        body = next((d for d in body.get("items", []) if d["name"] == args.dataset), None)
        if not body:
            print("  dataset not found")
            return 1
    ds_id = body["id"]

    field = {"name": "text", "title": "Text", "required": True,
             "settings": {"type": "text", "use_markdown": False}}
    status, body = http(base, "POST", f"/api/v1/datasets/{ds_id}/fields", token, payload=field)
    print_step("POST /api/v1/datasets/{id}/fields (use_markdown=false)", status)
    if status not in (201, 409):
        print(f"  {body}")
        return 1

    question = {"name": "label", "title": "Label", "required": True,
                "settings": {"type": "label_selection",
                             "options": [{"value": "good", "text": "Good"},
                                         {"value": "bad", "text": "Bad"}]}}
    status, body = http(base, "POST", f"/api/v1/datasets/{ds_id}/questions", token, payload=question)
    print_step("POST /api/v1/datasets/{id}/questions", status)
    if status not in (201, 409):
        print(f"  {body}")
        return 1

    # 4. publish (records can only be added to a published dataset)
    status, body = http(base, "PUT", f"/api/v1/datasets/{ds_id}/publish", token)
    print_step("PUT  /api/v1/datasets/{id}/publish", status)
    if status != 200:
        print(f"  {body}")
        return 1

    # 5./6. bulk-create positive and negative records
    status, body = http(base, "POST", f"/api/v1/datasets/{ds_id}/records/bulk", token,
                        payload=pos_body)
    pos_rec = body["items"][0]["id"] if status == 201 and body.get("items") else None
    print_step("POST /api/v1/datasets/{id}/records/bulk (positive: onerror)", status,
              f"record={pos_rec}" if pos_rec else "")
    if status != 201:
        print(f"  {body}")
        return 1

    status, body = http(base, "POST", f"/api/v1/datasets/{ds_id}/records/bulk", token,
                        payload=neg_body)
    neg_rec = body["items"][0]["id"] if status == 201 and body.get("items") else None
    print_step("POST /api/v1/datasets/{id}/records/bulk (negative: data-onerror)", status,
              f"record={neg_rec}" if neg_rec else "")
    if status != 201:
        print(f"  {body}")
        return 1

    # 7. ids for later steps
    ids = {"base_url": base, "workspace": args.workspace, "dataset": args.dataset,
           "dataset_id": ds_id, "positive_record_id": pos_rec,
           "negative_record_id": neg_rec,
           "annotate_url": f"{base}/dataset/{ds_id}/annotation-mode"}
    (here / "ids.json").write_text(json.dumps(ids, indent=2), encoding="utf-8")
    print("wrote ids.json")
    print(f"UI: {ids['annotate_url']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
