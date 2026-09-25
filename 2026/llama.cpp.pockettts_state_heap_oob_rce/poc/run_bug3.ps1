# Bug-3 reproduction driver (Windows side).
#
#   .\poc\run_bug3.ps1
#
# Windows-side counterpart of the repro package's run-exp.sh: that script needs a
# POSIX shell, so this drives the same container from PowerShell. The container
# command itself is not re-quoted here - it is read from poc/run_inside.sh, which
# is byte-identical to run-exp.sh's inner command line (argument lengths matter
# for the deterministic heap layout).
#
# Evidence produced:
#   <package>\logs\native.ps1.log   - full container transcript, contains NATIVE_EXIT
#   <package>\logs\R121             - marker written by the executed command
param(
    [string]$Image = 'pockettts-oob-rce:3d82ef62-focal-g915',
    [string]$PackageDir = ''
)

$ErrorActionPreference = 'Continue'
$PSNativeCommandUseErrorActionPreference = $false
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$pkg      = if ($PackageDir) { $PackageDir } else { Join-Path $repoRoot 'pockettts_gguf_oob_rce_minimal_codex_20260924' }
$pocDir   = $PSScriptRoot
$marker   = Join-Path $pkg 'logs\R121'
$log      = Join-Path $pkg 'logs\native.ps1.log'

if (-not (Test-Path $pkg)) { throw "repro package not found: $pkg" }

# Fresh state: a marker from an earlier run must not be mistaken for this one.
if (Test-Path $marker) {
    Move-Item -Force $marker (Join-Path $pkg 'logs\R121.previous')
}

docker run --rm --security-opt seccomp=unconfined `
    -v "${pkg}\models:/pockettts:ro" `
    -v "${pkg}:/pocketrce" `
    -v "${pocDir}:/pocketrce-poc:ro" `
    $Image -c "bash /pocketrce-poc/run_inside.sh" 2>&1 |
    Tee-Object -FilePath $log

if (-not (Test-Path $marker)) {
    Write-Host "FAIL: marker was not created" -ForegroundColor Red
    exit 1
}

Write-Host "PASS: artifact-only command execution"
Write-Host -NoNewline "marker: "
Get-Content $marker | ForEach-Object { Write-Host -NoNewline "$_ " }
Write-Host ""
Write-Host ("marker file : {0}" -f $marker)
Write-Host ("sha256      : {0}" -f (Get-FileHash $marker -Algorithm SHA256).Hash)
