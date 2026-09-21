#!/usr/bin/env bash
set -uo pipefail
mkdir -p /evidence/logs /out
# --- pin self-check (contract 5.3): deterministic source-tree digest -----------
# repositories/ holds vendored upstream deps that are not part of the A1111 commit,
# so they are moved aside for the digest and put back before the product starts.
mkdir -p /tmp/_aside
for d in repositories models extensions config.json; do
  [ -e "/app/webui/$d" ] && mv "/app/webui/$d" /tmp/_aside/
done
TREEHASH=$(python3 /work/treehash.py /app/webui | awk '{print $1}')
for d in repositories models extensions config.json; do
  [ -e "/tmp/_aside/$d" ] && mv "/tmp/_aside/$d" /app/webui/
done
export MBE2E_TREEHASH="$TREEHASH"
echo "$TREEHASH" > /evidence/logs/treehash.txt
HEAD=$(git -C /app/webui rev-parse HEAD 2>/dev/null || echo "no-git")
echo "$HEAD" > /evidence/logs/commit.txt
if [ "$TREEHASH" = "efbfdbe81a316f2e0758da403e8bb3e24dcd85c560bf369943372df936244905" ]; then
  export MBE2E_PIN_OK=1
else
  export MBE2E_PIN_OK=0
fi
cp /opt/pip_freeze.txt /evidence/logs/pip_freeze.txt
echo "mbe2e/v/a1111.extra_networks_filename_xss" > /evidence/logs/image.txt
printf '%s\n' "MBE2E-SENTINEL a1111.extra_networks_filename_xss" > /evidence/logs/SENTINEL

ARGS="-f --api --skip-prepare-environment --skip-torch-cuda-test --skip-version-check --no-half --use-cpu all --no-download-sd-model --skip-load-model-at-start --port 7860"
echo "bash webui.sh $ARGS --lora-dir <phase dir>" > /evidence/logs/command.txt
cd /app/webui
export venv_dir="-" python_cmd=python3
port_free () {
  python3 - <<'PYEOF'
import socket, sys
s = socket.socket()
s.settimeout(1)
try:
    s.connect(("127.0.0.1", 7860)); sys.exit(1)   # still listening
except Exception:
    sys.exit(0)                                    # free
PYEOF
}

stop_product () {
  pkill -f launch.py >/dev/null 2>&1
  pkill -f webui.sh  >/dev/null 2>&1
  for _ in $(seq 1 60); do pgrep -f launch.py >/dev/null 2>&1 || break; sleep 1; done
  pkill -9 -f launch.py >/dev/null 2>&1
  # a phase must not start while the previous product still owns the port,
  # otherwise the next phase silently talks to the old process
  for _ in $(seq 1 60); do port_free && break; sleep 1; done
  port_free || { echo "FATAL: port 7860 still held after stop_product"; ps aux | grep -i launch; }
  sleep 2
}

echo "=== phase neg ===" >> /evidence/logs/product_stdout.log
# shellcheck disable=SC2086
bash webui.sh $ARGS --lora-dir /app/webui/models/Lora_neg >> /evidence/logs/product_stdout.log 2>&1 &
( cd /work && /opt/pw/bin/python /work/drive.py neg ) > /evidence/logs/drive_neg.log 2>&1
stop_product

echo "=== phase pos ===" >> /evidence/logs/product_stdout.log
# shellcheck disable=SC2086
bash webui.sh $ARGS --lora-dir /app/webui/models/Lora_pos >> /evidence/logs/product_stdout.log 2>&1 &
( cd /work && /opt/pw/bin/python /work/drive.py pos ) > /evidence/logs/drive_pos.log 2>&1
stop_product

( cd /work && /opt/pw/bin/python /work/drive.py merge ) > /evidence/logs/drive.log 2>&1
RC=$?
cat /evidence/logs/drive.log
exit "$RC"
