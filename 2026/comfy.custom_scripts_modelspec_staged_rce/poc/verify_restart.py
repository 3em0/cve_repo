#!/usr/bin/env python3
"""Post-restart verification: did the overwritten initializer actually execute?

The staged initializer writes a marker containing its own pid, ppid, time and cwd.
Everything here is an assertion on that marker, on the process identity, and on
the file hashes -- nothing is inferred from the drive phase.

Checks:
  C1  the victim package's __init__.py is still exactly the staged file after restart
  C2  the marker exists (it did not before the restart -- plant.py asserted that)
  C3  the marker token matches the token baked into the staged initializer
  C4  the marker's pid is the pid of the RESTARTED product process, and differs from
      the pid that was running during the attack
  C5  the marker's mtime is after the restart
"""
import hashlib
import json
import os
import pathlib
import sys
import time

ROOT = pathlib.Path.home() / "cve_repro_modelspec"
RUN = pathlib.Path(os.environ.get("RUN_DIR", ROOT / "run"))
COMFY = pathlib.Path(os.environ.get("COMFY_ROOT", ROOT / "src/ComfyUI"))
MARKER = pathlib.Path(os.environ.get("MARKER_PATH", RUN / "staged_marker.json"))
VICTIM_INIT = COMFY / "custom_nodes" / "Victim-Demo-Pack" / "__init__.py"
TOKEN = "LCS-STAGED-CANARY custom_scripts_modelspec"


def sha256(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main() -> int:
    staged_sha = (RUN / "staged.sha256").read_text().strip()
    pid_now = int((RUN / "product.pid").read_text().strip())
    pid_attack = int((RUN / "attack_pid.txt").read_text().strip())
    restart_epoch = float((RUN / "restart_epoch.txt").read_text().strip())

    checks = {}
    checks["C1_initializer_still_staged"] = sha256(VICTIM_INIT) == staged_sha
    checks["C2_marker_exists"] = MARKER.exists()
    data = json.loads(MARKER.read_text()) if MARKER.exists() else {}
    checks["C3_token_matches"] = data.get("token") == TOKEN
    checks["C4_pid_is_restarted_process"] = data.get("pid") == pid_now and pid_now != pid_attack
    checks["C5_mtime_after_restart"] = MARKER.exists() and MARKER.stat().st_mtime >= restart_epoch

    out = {
        "victim_init_sha256": sha256(VICTIM_INIT),
        "staged_sha256": staged_sha,
        "marker_path": str(MARKER),
        "marker": data,
        "pid_during_attack": pid_attack,
        "pid_after_restart": pid_now,
        "checks": checks,
        "verdict": "EXECUTED" if all(checks.values()) else "NOT-EXECUTED",
    }
    for k, v in checks.items():
        print(f"  {'PASS' if v else 'FAIL'}  {k}")
    print()
    print("  marker:", json.dumps(data, sort_keys=True))
    print("  pid during attack :", pid_attack)
    print("  pid after restart :", pid_now)
    print()
    print("  VERDICT:", out["verdict"])

    (RUN / "restart.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n",
                                      encoding="utf-8")
    return 0 if out["verdict"] == "EXECUTED" else 1


if __name__ == "__main__":
    sys.exit(main())
