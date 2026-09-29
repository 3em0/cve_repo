#!/usr/bin/env bash
# One-shot runner for a single model file, for interactive/terminal use.
# Mirrors exactly what exp/drive.py's run_praat() does for each tag:
#   drop model_<tag>.bin into <prefs>/models/whispercpp/community-whisper.bin
#   (the folder Praat's own dialog names), then run
#   praat_barren --pref-dir=<prefs> --run script.praat
# with the same ASAN_OPTIONS drive.py uses.
#
# usage: run_one.sh benign|evil
set -eu
TAG="${1:?usage: run_one.sh benign|evil}"
ART=/artifact
OUT=/out
PRAAT=/src/praat/praat_barren

PREFS="$OUT/prefs_$TAG"
MODELS="$PREFS/models/whispercpp"
rm -rf "$PREFS"
rm -f "$OUT"/asan.*
mkdir -p "$MODELS" "$OUT/logs"
cp "$ART/model_$TAG.bin" "$MODELS/community-whisper.bin"

SCRIPT="$OUT/script_$TAG.praat"
printf 'Create SpeechRecognizer: "community-whisper.bin", "English"\n' > "$SCRIPT"

export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:log_path=$OUT/asan:exitcode=42"

set +e
"$PRAAT" "--pref-dir=$PREFS" --run "$SCRIPT"
RC=$?
set -e

echo "---- exit_code=$RC ----"
# ASan writes its report to /out/asan.<pid> (log_path); collect it under a
# deterministic name and show it here.
i=0
for f in "$OUT"/asan.*; do
  [ -e "$f" ] || continue
  cp -f "$f" "$OUT/logs/asan.$TAG.$i.txt"
  echo "---- ASan report: $f ----"
  cat "$f"
  i=$((i+1))
done
exit $RC
