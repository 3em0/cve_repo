"""Minimal in-process mock of the Hugging Face Hub HTTP endpoints used by
``huggingface_hub`` / ``transformers`` when a repository id is resolved.

Why this file exists
--------------------
The reproduction must show that the *identity* of the second-hop repository is
chosen by the LoRA adapter's ``adapter_config.json``. To keep the run offline
and network-bounded, the Hub endpoint is stood up on 127.0.0.1 and every file
it serves lives in a local directory tree:

    <HUB_ROOT>/<owner>/<name>/config.json
    <HUB_ROOT>/<owner>/<name>/model.safetensors
    ...

``huggingface_hub`` treats ``HF_ENDPOINT`` as "the Hub", so pointing it at this
server exercises the real download code path (HEAD for the etag/commit, GET for
the payload) without contacting huggingface.co.

Every request is appended to ``request_log`` so the report can show exactly
which repositories the victim process contacted.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

FAKE_COMMIT = "f" * 40


class _Handler(BaseHTTPRequestHandler):
    hub_root = "."
    request_log = None
    verbose = False
    repo_re = re.compile(r"/api/models/([^/?]+/[^/?]+)")
    file_re = re.compile(r"/([^/]+/[^/]+)/resolve/[^/?#]+/(.+)")
    # tree listing used by transformers 5's ``list_repo_templates``:
    # GET /api/models/<repo>/tree/<revision>[/<subpath>]?recursive=..&expand=..
    tree_re = re.compile(r"/api/models/([^/?]+/[^/?]+)/tree/([^/?]+)(?:/(.*))?$")

    # keep one clean line per request instead of the noisy default logging
    def log_request(self, code="-", size="-"):
        pass

    def log_message(self, fmt, *args):
        if not self.verbose:
            return
        sys.stderr.write("[mock-hub] " + (fmt % args) + "\n")
        sys.stderr.flush()

    def _record(self, method, path):
        if not self.request_log:
            return
        with open(self.request_log, "a", encoding="utf-8") as f:
            f.write("%-4s %s\n" % (method, path))

    def _send(self, code, body=b"", ctype="application/json", extra=None,
              write_body=True):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        # For HEAD, Content-Length must describe what a GET would return, so the
        # caller passes the real payload and only suppresses writing it.
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body and write_body:
            self.wfile.write(body)

    def do_HEAD(self):
        self._record("HEAD", self.path)
        path = self.path.split("?", 1)[0]
        if self.tree_re.match(path):
            self._send(200, b"[]", "application/json",
                       {"X-Repo-Commit": FAKE_COMMIT}, write_body=False)
            return
        m = self.repo_re.match(path)
        if m and "/resolve/" not in path:
            repo = m.group(1)
            exists = os.path.isdir(os.path.join(self.hub_root, *repo.split("/")))
            self._send(200 if exists else 404, b"", "application/json",
                       {"X-Repo-Commit": FAKE_COMMIT}, write_body=False)
            return
        self._serve_file(head_only=True)

    def _tree_entries(self, repo, subpath):
        """List files/directories under <hub_root>/<repo>/<subpath>."""
        base = os.path.join(self.hub_root, *repo.split("/"))
        target = os.path.normpath(os.path.join(base, subpath)) if subpath else base
        entries = []
        if os.path.isdir(target) and target.startswith(os.path.normpath(base)):
            for name in sorted(os.listdir(target)):
                full = os.path.join(target, name)
                rel = os.path.relpath(full, base).replace("\\", "/")
                if os.path.isfile(full):
                    with open(full, "rb") as f:
                        digest = hashlib.sha256(f.read()).hexdigest()
                    entries.append({"type": "file", "path": rel,
                                    "size": os.path.getsize(full), "oid": digest})
                else:
                    entries.append({"type": "directory", "path": rel})
        return entries

    def do_GET(self):
        self._record("GET", self.path)
        path = self.path.split("?", 1)[0]
        tree = self.tree_re.match(path)
        if tree:
            body = json.dumps(self._tree_entries(tree.group(1), tree.group(3) or "")).encode()
            self._send(200, body, extra={"X-Repo-Commit": FAKE_COMMIT})
            return
        m = self.repo_re.match(path)
        if m and "/resolve/" not in path:
            repo = m.group(1)
            repo_dir = os.path.join(self.hub_root, *repo.split("/"))
            if os.path.isdir(repo_dir):
                siblings = [{"rfilename": f} for f in sorted(os.listdir(repo_dir))]
                body = json.dumps(
                    {
                        "id": repo,
                        "sha": FAKE_COMMIT,
                        "siblings": siblings,
                        "private": False,
                        "gated": False,
                    }
                ).encode()
                self._send(200, body, extra={"X-Repo-Commit": FAKE_COMMIT})
            else:
                self._send(404, b'{"error":"Repository Not Found"}',
                           extra={"X-Repo-Commit": FAKE_COMMIT})
            return
        self._serve_file(head_only=False)

    def _serve_file(self, head_only):
        m = self.file_re.match(self.path)
        if not m:
            self._send(404, b"not found", extra={"X-Repo-Commit": FAKE_COMMIT})
            return

        repo, fname = m.group(1), m.group(2)
        fpath = os.path.normpath(os.path.join(self.hub_root, *repo.split("/"), fname))
        if not os.path.isfile(fpath):
            self.log_message("%s %s -> 404", "HEAD" if head_only else "GET", self.path)
            self._send(404, b'{"error":"Entry not found"}',
                       extra={"X-Repo-Commit": FAKE_COMMIT})
            return

        with open(fpath, "rb") as f:
            data = f.read()
        etag = hashlib.sha256(data).hexdigest()
        extra = {
            "X-Repo-Commit": FAKE_COMMIT,
            "ETag": '"%s"' % etag,
            "Accept-Ranges": "bytes",
        }
        self.log_message("%s %s -> 200 (%d bytes)", "HEAD" if head_only else "GET",
                         self.path, len(data))
        if head_only:
            self._send(200, data, "application/octet-stream", extra, write_body=False)
            return

        rng = self.headers.get("Range")
        if rng and rng.startswith("bytes="):
            start = int(rng.split("bytes=")[1].split("-")[0])
            chunk = data[start:]
            self.send_response(206)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Range",
                             "bytes %d-%d/%d" % (start, len(data) - 1, len(data)))
            self.send_header("Content-Length", str(len(chunk)))
            for k, v in extra.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(chunk)
            return

        self._send(200, data, "application/octet-stream", extra)


def start_server(port=8765, hub_root=".", request_log=None, verbose=False):
    """Start the mock Hub on 127.0.0.1:<port> in a daemon thread.

    ``request_log`` is the authoritative record of what the victim fetched;
    ``verbose`` only mirrors those lines to stderr for interactive debugging.
    """
    handler = type("BoundHandler", (_Handler,), {"hub_root": hub_root,
                                                 "request_log": request_log,
                                                 "verbose": verbose})
    srv = HTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
