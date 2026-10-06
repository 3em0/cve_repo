@echo off
rem Re-shoot runner: the first evidence pass showed only the tail of the 170-line
rem index JSON, so this batch re-runs the two index-inspection steps in the same
rem real cmd window (head shows the top of the index including the redirected key,
rem grep proves that exactly one entry names the pickle shard).
rem Usage: start capture_evidence.ps1 first, then start this file.

setlocal
title MEMO-POC-EVIDENCE 00-reshoot
mode con: cols=150 lines=45
cd /d "E:\Reproduce\memoavatar-memo_shard_index_defeats_use_safetensors_2026-10-06\poc"
echo on

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

@title MEMO-POC-EVIDENCE 99-done
echo.
echo re-shoot finished - window kept open on purpose
endlocal
