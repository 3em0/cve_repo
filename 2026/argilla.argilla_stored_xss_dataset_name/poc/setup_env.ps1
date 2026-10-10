# One-time environment setup for the Argilla stored-XSS PoC:
# creates .venv in this folder and installs the pinned versions.
#   - argilla-server 2.8.0 (PyPI wheel; bundles the production frontend)
#   - argilla (client) 2.8.0 - same release as the pinned commit 78cb5183f72e
#   - click < 8.2 (typer 0.9.x used by argilla-server 2.8.0 is incompatible
#     with click >= 8.2 CLI parsing)
# Requires Python 3.9+ (validated with 3.12) on PATH.

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    python -m venv .venv
}
& .venv\Scripts\python.exe -m pip install --upgrade pip
& .venv\Scripts\python.exe -m pip install `
    "argilla-server==2.8.0" "argilla==2.8.0" "click<8.2" httpx
& .venv\Scripts\python.exe -c "import argilla, argilla_server, importlib.metadata as m; print('client', m.version('argilla')); print('server', m.version('argilla-server'))"
Write-Host "setup done: .venv ready"
