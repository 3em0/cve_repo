"""In-process mock of the Hugging Face Hub endpoints used by hf_hub_download /
AutoModel.from_pretrained(trust_remote_code=True).

Serves any repository that exists as a subdirectory of HUB_ROOT:
    <HUB_ROOT>/<owner>/<name>/config.json
    <HUB_ROOT>/<owner>/<name>/*.py

Only file downloads over plain HTTP are implemented - enough to demonstrate
that transformers downloads the remote-code module from the repository named in
the victim's model package. Run in a daemon thread inside run_repro.py so the
whole reproduction stays on 127.0.0.1 and needs no internet access.
"""
import hashlib
import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class _Handler(BaseHTTPRequestHandler):
    hub_root = "."
    request_log = None  # optional file path: every resolved-file request is appended
    repo_re = re.compile(r"/api/models/([^/?]+/[^/?]+)")
    file_re = re.compile(r"/([^/]+/[^/]+)/resolve/[^/]+/(.+)")

    def log_request(self, code="-", size="-"):
        # silence the automatic per-request line; explicit log_message calls below
        # keep one line per request
        pass

    def log_message(self, fmt, *args):
        sys.stderr.write("[mock-hub] " + (fmt % args) + "\n")
        sys.stderr.flush()

    def _log_request(self, repo, fname, head_only):
        if not self.request_log:
            return
        with open(self.request_log, "a", encoding="utf-8") as f:
            f.write("%s %s/resolve/main/%s\n" % ("HEAD" if head_only else "GET ", repo, fname))

    def _send(self, code, body=b"", ctype="application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _commit(self):
        # stable per-repo fake commit sha so the hub cache layout is deterministic
        return ("f" * 40)

    def do_HEAD(self):
        self._serve_file(head_only=True)

    def do_GET(self):
        m = self.repo_re.match(self.path)
        if m:
            repo = m.group(1)
            if os.path.isdir(os.path.join(self.hub_root, *repo.split("/"))):
                siblings = sorted(
                    {"rfilename": f} for f in os.listdir(os.path.join(self.hub_root, *repo.split("/")))
                )
                siblings = [{"rfilename": f["rfilename"]} for f in siblings]
                body = json.dumps({"sha": self._commit(), "siblings": siblings}).encode()
                self._send(200, body, extra={"X-Repo-Commit": self._commit()})
            else:
                self._send(404, b"Repository Not Found", extra={"X-Repo-Commit": self._commit()})
            return
        self._serve_file(head_only=False)

    def _serve_file(self, head_only):
        m = self.file_re.match(self.path)
        if m:
            repo, fname = m.group(1), m.group(2).split("?")[0]
            self._log_request(repo, fname, head_only)
            fpath = os.path.normpath(os.path.join(self.hub_root, *repo.split("/"), fname))
            if os.path.isfile(fpath):
                with open(fpath, "rb") as f:
                    data = f.read()
                etag = hashlib.sha256(data).hexdigest()
                if head_only:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("X-Repo-Commit", self._commit())
                    self.send_header("ETag", '"%s"' % etag)
                    self.end_headers()
                    self.log_message("HEAD %s/%s -> 200 (%d bytes)", repo, fname, len(data))
                    return
                etag = hashlib.sha256(data).hexdigest()
                rng = self.headers.get("Range")
                if rng and rng.startswith("bytes="):
                    start = int(rng.split("bytes=")[1].split("-")[0])
                    chunk = data[start:]
                    self.log_message("GET %s/%s -> 206 [%d-%d]", repo, fname, start, len(data) - 1)
                    self.send_response(206)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Range", "bytes %d-%d/%d" % (start, len(data) - 1, len(data)))
                    self.send_header("Content-Length", str(len(chunk)))
                    self.send_header("X-Repo-Commit", self._commit())
                    self.send_header("ETag", '"%s"' % etag)
                    self.end_headers()
                    self.wfile.write(chunk)
                    return
                self.log_message("GET %s/%s -> 200 (%d bytes)", repo, fname, len(data))
                self._send(200, data, "application/octet-stream",
                           extra={"X-Repo-Commit": self._commit(), "ETag": '"%s"' % etag})
                return
            self.log_message("%s %s -> 404", "HEAD" if head_only else "GET", self.path.replace("/resolve/main", ""))
        self._send(404, b"not found", extra={"X-Repo-Commit": self._commit()})


def start_server(port=8765, hub_root=".", request_log=None):
    handler = type("BoundHandler", (_Handler,), {"hub_root": hub_root, "request_log": request_log})
    srv = HTTPServer(("127.0.0.1", port), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv
