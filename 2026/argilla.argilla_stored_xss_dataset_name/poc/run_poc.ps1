# Run the full PoC flow against a stack started with start_stack.ps1:
#   1. build the positive + negative disk-dataset packages
#   2. import the positive package (payload name stored server-side)
#   3. show the names exactly as stored (raw JSON API)
#   4. import the negative control and show the names again
# Then open the printed Settings URLs in a browser signed in as argilla / 1234:
#   - positive dataset: the canary element appears in the DOM (XSS triggered)
#   - negative dataset: plain text, no canary

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here
$py = Join-Path $here ".venv\Scripts\python.exe"

& python make_poc.py
& $py import_poc.py samples\poc-positive
& $py check_names.py
& $py import_poc.py samples\poc-negative
& $py check_names.py
Write-Host ""
Write-Host "Next (manual browser step): sign in at http://localhost:6900 as argilla / 1234"
Write-Host "and open the /dataset/<id>/settings URLs printed above."
