@echo off
rem Evidence runner v4. Each step: clear screen, run ONE command, flip the
rem console title to the step name after the command completes; the capture
rem monitor (capture_evidence.ps1) screenshots the window at every title
rem change. The driver runs write their console output to files inside the
rem container and the batch shows the last 20 lines, so the huge per-key
rem checkpoint-load chatter never floods the terminal.
title VITA-POC-EVIDENCE 01-env
cd /d "E:\Reproduce\VITA-MLLM-VITA_index.json_weight_map_to_pickle_2026-10-05\poc"
echo on
@cls
docker --version
@title VITA-POC-EVIDENCE 01-env
@ping -n 10 127.0.0.1 >nul
@cls
docker build -t vita-poc:35d064a6 .
@ping -n 3 127.0.0.1 >nul
@title VITA-POC-EVIDENCE 02-build
@ping -n 9 127.0.0.1 >nul
@cls
docker run -d --name vita-poc vita-poc:35d064a6
docker exec -d vita-poc python /work/poc/mock_hf_server.py
@ping -n 3 127.0.0.1 >nul
docker exec vita-poc python /work/poc/make_poc.py
@ping -n 2 127.0.0.1 >nul
@title VITA-POC-EVIDENCE 03-make-poc
@ping -n 9 127.0.0.1 >nul
@cls
docker exec vita-poc ls /work/poc/attacker_repo
@title VITA-POC-EVIDENCE 04-second-repo-files
@ping -n 9 127.0.0.1 >nul
@cls
docker exec vita-poc ls /opt/artifact/audio-approved
@title VITA-POC-EVIDENCE 05-approved-dir
@ping -n 9 127.0.0.1 >nul
@cls
docker exec vita-poc sh -c "python /work/poc/run_driver.py --arm positive > /work/poc/logs/driver_positive.out 2>&1"
@ping -n 2 127.0.0.1 >nul
docker exec vita-poc tail -n 20 /work/poc/logs/driver_positive.out
@title VITA-POC-EVIDENCE 06-positive-load
@ping -n 11 127.0.0.1 >nul
@cls
docker exec vita-poc cat /work/poc/logs/hf_mock.log
@title VITA-POC-EVIDENCE 07-positive-requests
@ping -n 9 127.0.0.1 >nul
@cls
docker exec vita-poc sh -c "python /work/poc/run_driver.py --arm negative > /work/poc/logs/driver_negative.out 2>&1"
@ping -n 2 127.0.0.1 >nul
docker exec vita-poc tail -n 20 /work/poc/logs/driver_negative.out
@title VITA-POC-EVIDENCE 08-negative-load
@ping -n 11 127.0.0.1 >nul
@cls
docker exec vita-poc cat /work/poc/logs/hf_mock.log
@title VITA-POC-EVIDENCE 09-negative-no-requests
@ping -n 11 127.0.0.1 >nul
@title VITA-POC-EVIDENCE 99-done
