<#
  run_repro.ps1 -- one-command setup for the robomimic pool_class eval() reproduction.

  Target : ARISE-Initiative/robomimic @ d309eaecc18acf4152a830a895a6984b8ac71b05
  Defect : robomimic/models/obs_core.py:121-122 -- eval(pool_class) on a string taken
           from config.observation.encoder.rgb.core_kwargs.pool_class, restored
           verbatim from the JSON embedded in a checkpoint.

  Creates %TEMP%\poc-work\robomimic-d309eae, pins the upstream source at the commit
  above into robomimic-src\, builds a venv that inherits the machine's torch, installs
  the pinned robomimic into it, and copies these PoC scripts next to it.

  Then run the scenario (see ../截图与复现指引.md):

    powershell -NoProfile -ExecutionPolicy Bypass -File real_terminal_shot.ps1 `
        -Scenario shot_scenario.json -OutDir ..\screenshots

  Requires: git, and a Python 3.10+ interpreter exposing torch + torchvision.
#>
[CmdletBinding()]
param(
    # Kept deliberately short: the captured terminal screenshots must not wrap their
    # lines. Override freely -- every path is derived from this one.
    [string]$WorkDir = 'C:\pocw',
    [string]$CanaryDir = 'C:\out',
    [string]$Python = 'python'
)

$ErrorActionPreference = 'Stop'
$Commit = 'd309eaecc18acf4152a830a895a6984b8ac71b05'
$RepoUrl = 'https://github.com/ARISE-Initiative/robomimic.git'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "==> work dir: $WorkDir"
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

# ---------------------------------------------------------------- pinned source
$Src = Join-Path $WorkDir 'robomimic-src'
if (-not (Test-Path (Join-Path $Src '.git'))) {
    Write-Host "==> cloning $RepoUrl"
    git clone --quiet $RepoUrl $Src
}
Write-Host "==> checking out $Commit"
git -C $Src checkout --quiet $Commit
$head = (git -C $Src rev-parse HEAD).Trim()
if ($head -ne $Commit) { throw "pinned commit mismatch: $head" }
Write-Host "    HEAD = $head"

# ----------------------------------------------------------------------- venv
$Venv = Join-Path $WorkDir '.venv'
if (-not (Test-Path $Venv)) {
    Write-Host "==> creating venv (inherits system torch/torchvision)"
    & $Python -m venv --system-site-packages $Venv
}
$VenvPy = Join-Path $Venv 'Scripts\python.exe'
if (-not (Test-Path $VenvPy)) { $VenvPy = Join-Path $Venv 'bin/python' }

& $VenvPy -c "import torch, torchvision" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "==> torch not importable; installing CPU wheels (large download)"
    & $VenvPy -m pip install --index-url https://download.pytorch.org/whl/cpu torch torchvision
}

Write-Host "==> installing robomimic runtime deps"
& $VenvPy -m pip install --quiet --disable-pip-version-check h5py huggingface_hub termcolor

Write-Host "==> installing pinned robomimic (editable, --no-deps)"
& $VenvPy -m pip install --quiet --disable-pip-version-check --no-deps -e $Src

# Upstream's own setup step: copies robomimic/macros.py -> robomimic/macros_private.py
# inside the pinned tree. Silences the "No private macro file found!" banner so the
# captured terminal output stays readable. Contained entirely in $Src.
$Macros = Join-Path $Src 'robomimic\macros_private.py'
if (-not (Test-Path $Macros)) {
    Write-Host "==> upstream macro setup"
    & $VenvPy (Join-Path $Src 'robomimic\scripts\setup_macros.py') | Out-Null
}

# --------------------------------------------------------------- poc material
Write-Host "==> copying PoC scripts"
Copy-Item (Join-Path $Here '*.py') $WorkDir -Force

# The payload writes to the absolute path /out/pwned_by_robomimic_pool_class.
# On POSIX that is /out; on Windows an absolute-looking POSIX path resolves against
# the current drive root, so it lands in <drive>:\out -- pre-create it.
Write-Host "==> canary directory: $CanaryDir"
New-Item -ItemType Directory -Force -Path $CanaryDir | Out-Null
Remove-Item (Join-Path $CanaryDir '*') -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "==> ready. Next:"
Write-Host "    cd `"$WorkDir`""
Write-Host "    $VenvPy env_check.py"
Write-Host "    $VenvPy make_poc.py"
Write-Host "    $VenvPy show_diff.py"
Write-Host "    $VenvPy victim.py ckpt/benign.pth      # negative control"
Write-Host "    $VenvPy victim.py ckpt/malicious.pth   # exploit"
