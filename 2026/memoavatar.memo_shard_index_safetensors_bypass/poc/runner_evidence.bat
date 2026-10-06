@echo off
rem Evidence runner for the MEMO shard-index PoC (15 screenshot steps).
rem
rem Why a batch runner instead of a keystroke driver: this desktop is shared with
rem other automation sessions, and a focus-stealing typing driver would type into
rem whichever window happens to be in front. This runner executes ONE command per
rem step inside its own real cmd window (echo on, so every command line and prompt
rem is echoed by cmd itself), then flips the console title to the step name; the
rem companion monitor poc\capture_evidence.ps1 screenshots the real window at every
rem title change without activating or typing into it.
rem
rem Usage: start capture_evidence.ps1 first, then start this file.
rem Note: make sure no older window with a MEMO-POC-EVIDENCE title is still open,
rem otherwise the monitor may latch onto the wrong window.

setlocal
title MEMO-POC-EVIDENCE 00-start
mode con: cols=150 lines=45
cd /d "E:\Reproduce\memoavatar-memo_shard_index_defeats_use_safetensors_2026-10-06\poc"
echo on

@cls
docker --version
@title MEMO-POC-EVIDENCE 01-env-docker
@ping -n 11 127.0.0.1 >nul

@cls
docker build -t memo-poc:151b0243 .
@ping -n 4 127.0.0.1 >nul
@title MEMO-POC-EVIDENCE 02-build
@ping -n 11 127.0.0.1 >nul

@cls
docker run -d --name memo-poc memo-poc:151b0243
@ping -n 6 127.0.0.1 >nul

@cls
docker exec memo-poc pip show torch accelerate
@ping -n 4 127.0.0.1 >nul
@title MEMO-POC-EVIDENCE 03-env-torch-accelerate
@ping -n 11 127.0.0.1 >nul

@cls
docker exec memo-poc pip show diffusers transformers
@ping -n 4 127.0.0.1 >nul
@title MEMO-POC-EVIDENCE 04-env-diffusers-transformers
@ping -n 11 127.0.0.1 >nul

@cls
docker exec memo-poc sed -n 140,155p /opt/memo/inference.py
@ping -n 4 127.0.0.1 >nul
@title MEMO-POC-EVIDENCE 05-product-call
@ping -n 11 127.0.0.1 >nul

@cls
docker exec memo-poc python make_poc.py
@ping -n 4 127.0.0.1 >nul
@title MEMO-POC-EVIDENCE 06-make-poc
@ping -n 14 127.0.0.1 >nul

@cls
docker exec memo-poc cat SHA256SUMS.txt
@ping -n 4 127.0.0.1 >nul
@title MEMO-POC-EVIDENCE 07-sha256sums
@ping -n 11 127.0.0.1 >nul

@cls
docker exec memo-poc head -n 12 out/memo_model_index_bin/reference_net/diffusion_pytorch_model.safetensors.index.json
@ping -n 4 127.0.0.1 >nul
@title MEMO-POC-EVIDENCE 08-index-positive
@ping -n 11 127.0.0.1 >nul

@cls
docker exec memo-poc grep -n second_stage.bin out/memo_model_index_bin/reference_net/diffusion_pytorch_model.safetensors.index.json
@ping -n 4 127.0.0.1 >nul
@title MEMO-POC-EVIDENCE 09-index-grep
@ping -n 11 127.0.0.1 >nul

@cls
docker exec memo-poc ls -l out/memo_model_index_bin/reference_net
@ping -n 4 127.0.0.1 >nul
@title MEMO-POC-EVIDENCE 10-arm-files
@ping -n 11 127.0.0.1 >nul

@cls
docker exec memo-poc python run_poc.py out/memo_model_index_bin
@ping -n 4 127.0.0.1 >nul
@title MEMO-POC-EVIDENCE 11-positive-payload
@ping -n 11 127.0.0.1 >nul

@cls
docker exec memo-poc cat out/RCE_MARKER_MEMO_SHARD_INDEX.txt
@ping -n 4 127.0.0.1 >nul
@title MEMO-POC-EVIDENCE 12-marker
@ping -n 11 127.0.0.1 >nul

@cls
docker exec memo-poc python run_poc.py out/memo_model_index_safe
@ping -n 4 127.0.0.1 >nul
@title MEMO-POC-EVIDENCE 13-negative-clean
@ping -n 11 127.0.0.1 >nul

@cls
docker exec memo-poc python run_poc.py out/memo_model_noindex
@ping -n 4 127.0.0.1 >nul
@title MEMO-POC-EVIDENCE 14-noindex-clean
@ping -n 11 127.0.0.1 >nul

@cls
docker exec memo-poc python run_poc.py out/memo_model_index_bin --guard
@ping -n 4 127.0.0.1 >nul
@title MEMO-POC-EVIDENCE 15-guard-contrast
@ping -n 12 127.0.0.1 >nul

@title MEMO-POC-EVIDENCE 99-done
echo.
echo evidence run finished - window kept open on purpose
endlocal
