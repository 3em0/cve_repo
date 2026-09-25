# Bug-2 reproduction driver (Windows side).
#
#   .\poc\run_bug2.ps1
#
# Runs the lab container's own ASan canary script (exp/oobwrite/run_asan.sh) against
# the minicpmv bucket_coords stack overflow: evil artifact (patch_size = 1) vs benign
# artifact (patch_size = 16).
#
# Two deliberate details:
#   * the image's entrypoint (setarch -R bash) is kept, because AddressSanitizer
#     cannot initialise on kernels with 32-bit mmap_rnd_bits - that is exactly why
#     the lab image disables ASLR for the process tree.  Overriding the entrypoint
#     with a bare bash makes the product die with a bare SIGSEGV and no report.
#   * the run happens on a copy of exp/oobwrite, so the original evidence tree is
#     never overwritten by the artifact builder or the log files.
#
# Evidence produced (all under poc/out/):
#   run_asan.console.log    - container transcript
#   asan_exit_codes.txt     - exit code per case
#   asan_evil.stderr        - sanitizer report of the positive run
#   asan_benign.stderr      - negative control
param(
    [string]$Image = 'llamacpp-mmproj-asan:3d82ef62'
)

$ErrorActionPreference = 'Continue'
$PSNativeCommandUseErrorActionPreference = $false

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$src      = Join-Path $repoRoot 'exp\oobwrite'
if (-not (Test-Path $src)) { throw "repro tree not found: $src" }

$work = Join-Path $env:TEMP 'cve_report_tmp\oobwrite-run'
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
New-Item -ItemType Directory -Force -Path $work | Out-Null
Copy-Item "$src\*" $work -Recurse -Force
Remove-Item (Join-Path $work 'logs') -Recurse -Force -ErrorAction SilentlyContinue

$out = Join-Path $PSScriptRoot 'out'
New-Item -ItemType Directory -Force -Path $out | Out-Null

docker run --rm --security-opt seccomp=unconfined --entrypoint setarch `
    -v "${work}:/oobwrite" `
    $Image -R bash -c "bash /oobwrite/run_asan.sh" 2>&1 |
    Tee-Object -FilePath (Join-Path $out 'run_asan.console.log')

Copy-Item (Join-Path $work 'logs\*') $out -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "--- exit codes ---"
Get-Content (Join-Path $out 'asan_exit_codes.txt') -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }

Write-Host "--- sanitizer signature (positive / evil artifact) ---"
$evil = Join-Path $out 'asan_evil.stderr'
if (Test-Path $evil) {
    Select-String -Path $evil -Pattern 'ERROR: AddressSanitizer|WRITE of size|stack-buffer-overflow|is located|SUMMARY:' |
        Select-Object -First 8 | ForEach-Object { Write-Host $_.Line.Trim() }
    Write-Host "top frames:"
    Select-String -Path $evil -Pattern '^\s+#0 |^\s+#1 |^\s+#2 |^\s+#3 ' |
        Select-Object -First 4 | ForEach-Object { Write-Host $_.Line.Trim() }
} else {
    Write-Host "(no stderr captured)"
}

Write-Host "--- negative control (benign artifact) ---"
$ben = Join-Path $out 'asan_benign.stderr'
if (Test-Path $ben) {
    $hits = Select-String -Path $ben -Pattern 'ERROR: AddressSanitizer|stack-buffer-overflow'
    if ($hits) { $hits | ForEach-Object { Write-Host $_.Line.Trim() } }
    else { Write-Host "no AddressSanitizer report (as expected)" }
}
