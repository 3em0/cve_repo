# Bug-1 reproduction driver (Windows side).
#
#   .\poc\run_bug1.ps1
#
# Drives the lab image's own entry point (exp/drive.py), which runs the product's
# real CLI twice - once with a well-formed mmproj (negative control) and once with
# the crafted one - and writes its verdict to /out/result.json.
#
# Evidence produced (all under poc/out/):
#   result.json                  - verdict, sanitizer signature, artifact hashes
#   logs/asan.evil.*.txt         - AddressSanitizer report of the positive run
#   logs/product_stderr.*.log    - the product's own stderr for both runs
param(
    [string]$Image = 'llamacpp-mmproj-asan:3d82ef62'
)

$ErrorActionPreference = 'Stop'
$out = Join-Path $PSScriptRoot 'out'
New-Item -ItemType Directory -Force -Path $out | Out-Null

docker run --rm --security-opt seccomp=unconfined `
    -v "${out}:/out" `
    $Image 2>&1 | Tee-Object -FilePath (Join-Path $out 'drive.stdout.log')

Write-Host ""
& (Join-Path $PSScriptRoot 'show_result.ps1') (Join-Path $out 'result.json')

Write-Host ""
Write-Host "--- AddressSanitizer report (first lines of the positive run) ---"
Get-ChildItem (Join-Path $out 'logs\asan.evil.*.txt') -ErrorAction SilentlyContinue | ForEach-Object {
    Get-Content $_.FullName -TotalCount 14 | ForEach-Object { Write-Host $_ }
}
