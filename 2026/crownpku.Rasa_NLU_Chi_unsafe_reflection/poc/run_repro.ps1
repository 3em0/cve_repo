# One-click reproduction environment for the Rasa_NLU_Chi unsafe-reflection PoC.
# Creates C:\pocw\rasanlu with: pinned source (commit f995c06e5aee),
# a CPython 3.12 venv, the minimal dependency set, and rasa_nlu installed
# from the pinned source with --no-deps. Then copy the PoC scripts in place.
$ErrorActionPreference = "Stop"

$work = "C:\pocw\rasanlu"
$commit = "f995c06e5aee5b6f68ea877c1a271667357a1c68"

New-Item -ItemType Directory -Force -Path $work | Out-Null
Set-Location $work

if (-not (Test-Path "$work\src\.git")) {
    git clone https://github.com/crownpku/Rasa_NLU_Chi.git "$work\src"
}
git -C "$work\src" checkout $commit

if (-not (Test-Path "$work\.venv\Scripts\python.exe")) {
    py -V:3.12 -m venv "$work\.venv"
}
& "$work\.venv\Scripts\python.exe" -m pip install -r "$PSScriptRoot\requirements-minimal.txt"
& "$work\.venv\Scripts\python.exe" -m pip install --no-deps "$work\src"

Copy-Item "$PSScriptRoot\make_poc.py","$PSScriptRoot\run_poc.py","$PSScriptRoot\show_code.py" -Destination $work -Force

Write-Host ""
Write-Host "Environment ready at $work (rasa_nlu from pinned commit $commit)"
Write-Host "Next: cd $work, then run the evidence chain shown in 截图与复现指引.md"
