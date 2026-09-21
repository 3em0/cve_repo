#!/usr/bin/env bash
# Start the real product, then drive it from outside with an ordinary HTTP client.
set -uo pipefail
mkdir -p /evidence/logs /out

HEAD=$(git -C /app/webui rev-parse HEAD)
echo "$HEAD" > /evidence/logs/commit.txt
if [ "$HEAD" = "$A1111_COMMIT" ]; then export MBE2E_PIN_OK=1; else export MBE2E_PIN_OK=0; fi
cp /opt/pip_freeze.txt /evidence/logs/pip_freeze.txt
echo "mbe2e/v/a1111.safetensors_yaml_target" > /evidence/logs/image.txt
printf '%s\n' "MBE2E-SENTINEL a1111.safetensors_yaml_target" > /evidence/logs/SENTINEL

CMD='bash webui.sh -f --api --skip-prepare-environment --skip-torch-cuda-test --skip-version-check --no-half --use-cpu all --no-download-sd-model --skip-load-model-at-start --port 7860'
echo "$CMD" > /evidence/logs/command.txt

cd /app/webui
export venv_dir="-" python_cmd=python3
# shellcheck disable=SC2086
$CMD > /evidence/logs/product_stdout.log 2>&1 &
PROD=$!

( cd /work && python3 /work/drive.py ) > /evidence/logs/drive.log 2>&1
RC=$?
cat /evidence/logs/drive.log

kill "$PROD" 2>/dev/null
pkill -f launch.py 2>/dev/null
sleep 1
exit "$RC"
