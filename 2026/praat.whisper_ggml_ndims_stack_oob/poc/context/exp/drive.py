#!/usr/bin/env python3
"""Drive Praat as an ordinary user would.

The victim installs a community Whisper model where Praat's own dialog tells
them to -- <preferences folder>/models/whispercpp/ -- and then runs the
Objects > New > Speech-to-text recognition > "Create SpeechRecognizer..."
command.  In batch mode that is exactly:

    praat_barren --pref-dir=<prefs> --run script.praat

with the one-line script

    Create SpeechRecognizer: "<model file name>", "English"

Nothing here imports, patches or reimplements anything from Praat.
"""
import glob
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

SRC = "/src/praat"
PRAAT = "/src/praat/praat_barren"
ART = pathlib.Path("/artifact")
OUT = pathlib.Path("/out")
LOGS = OUT / "logs"
EXPECTED = json.loads((ART / "expected.json").read_text())
MEMSAFETY = ("heap-buffer-overflow", "global-buffer-overflow",
             "stack-buffer-overflow", "heap-use-after-free", "SEGV")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


ADDR = re.compile(r"0x[0-9a-fA-F]+")
PIDLINE = re.compile(r"==\d+==")
THREAD = re.compile(r"\bT\d+\b")
FRAME = re.compile(r"^\s*#(\d+) 0x[0-9a-f]+ in (.+)$")


def normalise(text):
    t = PIDLINE.sub("==PID==", text)
    t = ADDR.sub("0xADDR", t)
    t = THREAD.sub("TN", t)
    t = t.replace(SRC + "/", "")
    t = re.sub(r"\(BuildId: [0-9a-f]+\)", "(BuildId: ID)", t)
    return t


def parse_asan(text):
    sig = {"error": None, "access": None, "access_size": None, "frames": []}
    m = re.search(r"ERROR: AddressSanitizer: ([A-Za-z\-]+)", text)
    if not m:
        return None
    sig["error"] = m.group(1)
    sig["memory_safety_violation"] = int(any(k in sig["error"] for k in MEMSAFETY))
    m = re.search(r"(WRITE|READ) of size (\d+)", text)
    if m:
        sig["access"] = m.group(1)
        sig["access_size"] = int(m.group(2))
    m = re.search(r"\[(\d+), (\d+)\) '(\w+)' \(line (\d+)\) "
                  r"<== Memory access at offset (\d+) overflows this variable", text)
    if m:
        sig["overflowed_object"] = m.group(3)
        sig["overflowed_object_declared_at_line"] = int(m.group(4))
        sig["overflowed_object_extent"] = [int(m.group(1)), int(m.group(2))]
        sig["access_at_frame_offset"] = int(m.group(5))
    body = text.split("ERROR: AddressSanitizer", 1)[1]
    for line in body.splitlines():
        fm = FRAME.match(line)
        if not fm:
            continue
        frame = fm.group(2).replace(SRC + "/", "")
        frame = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", frame)
        frame = re.sub(r"\(BuildId: [0-9a-f]+\)", "(BuildId: ID)", frame)
        sig["frames"].append(frame)
        if len(sig["frames"]) >= 10:
            break
    return sig


def clear_reports():
    for p in glob.glob("/out/asan.*"):
        os.unlink(p)


def collect_reports():
    asan, ubsan, texts = [], [], []
    for p in sorted(glob.glob("/out/asan.*")):
        t = pathlib.Path(p).read_text(errors="replace")
        texts.append(t)
        if "ERROR: AddressSanitizer" in t:
            asan.append(t)
        elif "runtime error:" in t:
            ubsan.append(t)
    return asan, ubsan, texts


def run_praat(tag, model_src):
    prefs = OUT / f"prefs_{tag}"
    models = prefs / "models" / "whispercpp"
    if prefs.exists():
        shutil.rmtree(prefs)
    models.mkdir(parents=True)
    # The victim's single action before running Praat: drop the downloaded model
    # into the folder Praat's own dialog names.
    shutil.copyfile(model_src, models / "community-whisper.bin")

    script = OUT / f"script_{tag}.praat"
    script.write_text('Create SpeechRecognizer: "community-whisper.bin", "English"\n')

    argv = [PRAAT, f"--pref-dir={prefs}", "--run", str(script)]
    clear_reports()
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = ("detect_leaks=0:abort_on_error=0:"
                           "log_path=/out/asan:exitcode=42")
    proc = subprocess.run(argv, capture_output=True, env=env, timeout=600,
                          encoding="utf-8", errors="replace")
    asan, ubsan, texts = collect_reports()
    (LOGS / f"product_stdout.{tag}.log").write_text(normalise(proc.stdout))
    (LOGS / f"product_stderr.{tag}.log").write_text(normalise(proc.stderr))
    for i, t in enumerate(texts):
        (LOGS / f"asan.{tag}.{i}.txt").write_text(normalise(t))
    both = normalise(proc.stdout + proc.stderr)
    return {
        "argv": [os.path.basename(argv[0])] + [f"--pref-dir=<prefs_{tag}>",
                                               "--run", f"<script_{tag}.praat>"],
        "script": 'Create SpeechRecognizer: "community-whisper.bin", "English"',
        "model_placed_at": "<prefs>/models/whispercpp/community-whisper.bin",
        "exit_code": proc.returncode,
        "asan_error_reports": len(asan),
        "ubsan_only_reports": len(ubsan),
        "signature": parse_asan(asan[0]) if asan else None,
        "praat_reported_context_failure": int("Cannot create Whisper context" in both),
        "tail": "\n".join(both.strip().splitlines()[-6:]),
    }


def main():
    LOGS.mkdir(parents=True, exist_ok=True)
    commit = subprocess.run(["git", "-C", SRC, "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=True).stdout.strip()
    commit_ok = commit == EXPECTED["product"]["pinned_commit"]
    (LOGS / "image.txt").write_text(os.environ.get("MBE2E_IMAGE", "") + "\n")
    (LOGS / "command.txt").write_text(
        "praat_barren --pref-dir=<prefs> --run script.praat\n"
        '  script: Create SpeechRecognizer: "community-whisper.bin", "English"\n')
    freeze = subprocess.run([sys.executable, "-m", "pip", "freeze"],
                            capture_output=True, text=True)
    (LOGS / "pip_freeze.txt").write_text(freeze.stdout)

    benign = run_praat("benign", ART / "model_benign.bin")
    evil = run_praat("evil", ART / "model_evil.bin")

    canary_hit = int(evil["signature"] is not None
                     and evil["signature"].get("memory_safety_violation") == 1
                     and any("whisper_model_load" in f
                             for f in evil["signature"]["frames"]))
    negctl_clean = int(benign["asan_error_reports"] == 0)

    result = {
        "root_key": "praat.whisper_ggml_ndims_stack_oob",
        "product": {
            "repo": EXPECTED["product"]["repo"],
            "pinned_commit": commit,
            "pinned_commit_matches_expected": int(commit_ok),
            "build_type": EXPECTED["product"]["build_type"],
            "sanitizers": EXPECTED["product"]["sanitizers"],
            "entrypoint": "praat_barren --run (batch mode, no GUI)",
        },
        "artifacts": {k: {"name": f"model_{k}.bin",
                          "sha256": sha256(ART / f"model_{k}.bin")}
                      for k in ("evil", "benign")},
        "artifact_sha256_matches_expected": int(
            sha256(ART / "model_evil.bin") == EXPECTED["artifact"]["evil_sha256"]),
        "negative_control": benign,
        "positive": evil,
        "sink_effect": "asan_report" if canary_hit else "none",
        "canary_hit": canary_hit,
        "negative_control_clean": negctl_clean,
        "verdict": "PASS" if (canary_hit and negctl_clean and commit_ok) else "FAIL",
    }
    (OUT / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
