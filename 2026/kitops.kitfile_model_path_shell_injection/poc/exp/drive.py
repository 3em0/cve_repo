#!/usr/bin/env python3
"""Drive kitops as a normal user would: `kit dev start <modelkit-dir>`.

This script NEVER imports or links the project under test -- kitops is a Go
binary and it is started as a real child process.  Between cases we use the
product's own `kit dev stop`, because `LLMHarness.Start` refuses to run while a
previous dev server is recorded as alive.
"""
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time

sys.path.insert(0, "/work/exp")
from treehash import tree_sha256  # local helper, not part of the product

REPO = pathlib.Path("/work/kitops")
ART = pathlib.Path("/artifact")
OUT = pathlib.Path("/out")
LOGS = pathlib.Path("/work/exp/logs")
EXPECTED = json.loads(pathlib.Path("/work/example/expected.json").read_text())
CANARY = pathlib.Path(EXPECTED["canary"]["path"])
HARNESS = pathlib.Path("/root/.local/share/kitops/harness")


def sh(cmd, cwd=None, timeout=300):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                          timeout=timeout, env={**os.environ})


def stop():
    """The product's own teardown command; also clears a stale pid record."""
    sh(["kit", "dev", "stop"])
    pid = HARNESS / "process.pid"
    if pid.exists():
        pid.unlink()


WAIT_S = 20.0  # kitops spawns the harness asynchronously (cmd.Start()), so give
               # the child shell a bounded window to run before we look at /out.


def dev_start(ctx, tag, port):
    """One ordinary user action: `kit dev start <directory>`."""
    cmd = ["kit", "dev", "start", str(ctx), "--port", str(port)]
    r = sh(cmd)
    # bounded wait: exits early as soon as the canary lands, otherwise WAIT_S.
    deadline = time.monotonic() + WAIT_S
    while time.monotonic() < deadline and not CANARY.exists():
        time.sleep(0.25)
    harness_log = ""
    hl = HARNESS / "harness.log"
    if hl.exists():
        harness_log = hl.read_text()[:2000]
    listing = subprocess.run(["find", str(ctx), "-mindepth", "1"],
                             capture_output=True, text=True).stdout
    (LOGS / f"product_stdout.{tag}.log").write_text(
        "$ " + " ".join(cmd) + "\n--- stdout ---\n" + r.stdout
        + "\n--- stderr ---\n" + r.stderr
        + "\n--- harness.log ---\n" + harness_log
        + "\n--- modelkit tree ---\n" + listing)
    return {
        "argv": cmd,
        "returncode": r.returncode,
        "server_started": "Development server started" in (r.stdout + r.stderr),
        "stderr_first_line": (r.stderr.strip().splitlines() or [""])[0],
    }


def canary_state():
    if not CANARY.exists():
        return {"present": False, "content": None, "sha256": None}
    body = CANARY.read_text()
    return {"present": True, "content": body,
            "sha256": hashlib.sha256(body.encode()).hexdigest()}


def clear():
    if CANARY.exists():
        CANARY.unlink()


def tree_digest(root):
    out = {}
    for p in sorted(pathlib.Path(root).rglob("*")):
        if p.is_file():
            out[str(p.relative_to(ART))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def main():
    LOGS.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)

    head = tree_sha256(str(REPO))
    (LOGS / "pip_freeze.txt").write_text(
        sh([sys.executable, "-m", "pip", "freeze"]).stdout)
    (LOGS / "command.txt").write_text("kit dev start /artifact/<kit>\n")
    (LOGS / "SENTINEL").write_text(EXPECTED["canary"]["content"] + "\n")
    kit_version = sh(["kit", "version"]).stdout.strip()
    provenance = pathlib.Path("/work/harness_provenance.txt").read_text().strip()

    cases = []

    stop(); clear()
    run = dev_start(ART / "benign_kit", "negative_benign", 18081)
    cases.append({"case": "N1_benign_kit", "expect_canary": False,
                  "run": run, "canary": canary_state()})

    stop(); clear()
    run = dev_start(ART / "nogguf_kit", "negative_nogguf", 18082)
    cases.append({"case": "N2_no_gguf", "expect_canary": False,
                  "run": run, "canary": canary_state()})

    stop(); clear()
    run = dev_start(ART / "evil_kit", "attack", 18083)
    cases.append({"case": "A1_model_path_shell_injection", "expect_canary": True,
                  "run": run, "canary": canary_state()})
    stop()

    verdict_ok = (
        all(c["canary"]["present"] is c["expect_canary"] for c in cases)
        and cases[-1]["canary"]["content"] == EXPECTED["canary"]["content"]
        and head == EXPECTED["source_tree_sha256"]
    )

    result = {
        "root_key": EXPECTED["root_key"],
        "product": EXPECTED["product"],
        "product_commit_expected": EXPECTED["product_commit"],
        "source_tree_sha256_expected": EXPECTED["source_tree_sha256"],
        "source_tree_sha256_actual": head,
        "product_commit_verified": head == EXPECTED["source_tree_sha256"],
        "product_entrypoint": EXPECTED["product_entrypoint"],
        "kit_version": kit_version,
        "harness_binary_provenance": provenance,
        "artifact_sha256": tree_digest(ART),
        "sink": EXPECTED["sink"],
        "canary_path": str(CANARY),
        "cases": cases,
        "network": "none",
        "verdict": "PASS" if verdict_ok else "FAIL",
        "achieved_grade": EXPECTED["expected_grade"] if verdict_ok else "blocked",
    }
    body = json.dumps(result, indent=2, sort_keys=True) + "\n"
    # a human-readable trace of what this driver did, in order
    trace = ["driver: exp/drive.py (never imports the project under test)",
             "product pin self-check: %s == %s -> %s" % (
                 result["source_tree_sha256_actual"],
                 result["source_tree_sha256_expected"],
                 result["product_commit_verified"])]
    for c in result["cases"]:
        trace.append("case %-32s argv=%s rc=%s canary_expected=%s canary_present=%s content=%r"
                     % (c["case"], " ".join(map(str, c["run"]["argv"])),
                        c["run"]["returncode"], c["expect_canary"],
                        c["canary"]["present"], c["canary"]["content"]))
    trace.append("verdict=%s achieved_grade=%s" % (result["verdict"], result["achieved_grade"]))
    (LOGS / "drive.log").write_text("\n".join(trace) + "\n")
    pathlib.Path("/work/exp/result.json").write_text(body)
    (OUT / "result.json").write_text(body)
    print(json.dumps({"verdict": result["verdict"],
                      "commit_verified": result["product_commit_verified"]}))
    return 0 if verdict_ok else 1


if __name__ == "__main__":
    sys.exit(main())
