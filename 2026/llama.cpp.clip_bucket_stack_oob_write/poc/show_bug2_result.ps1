# One-screen summary of the bug-2 run: exit code per case plus the sanitizer verdict.
#
#   .\poc\show_bug2_result.ps1
#
# Reads the evidence written by poc/run_bug2.ps1 (poc/out/) and prints only the
# decisive lines, so a screenshot of this command proves exactly one thing.
$ErrorActionPreference = 'Continue'

$out   = Join-Path $PSScriptRoot 'out'
$codes = Join-Path $out 'asan_exit_codes.txt'
$evil  = Join-Path $out 'asan_evil.stderr'
$ben   = Join-Path $out 'asan_benign.stderr'

foreach ($f in @($codes, $evil, $ben)) {
    if (-not (Test-Path $f)) { throw "missing evidence file: $f (run .\poc\run_bug2.ps1 first)" }
}

"artifact   : mmproj_evil_bucket.gguf   (clip.vision.patch_size = 1  -> pos = 2048)"
"control    : mmproj_benign_bucket.gguf (clip.vision.patch_size = 16 -> pos = 128)"
""

$evilLine = Select-String -Path $evil -Pattern 'ERROR: AddressSanitizer' | Select-Object -First 1
$writeLine = Select-String -Path $evil -Pattern 'WRITE of size' | Select-Object -First 1
$sumLine  = Select-String -Path $evil -Pattern 'SUMMARY: AddressSanitizer' | Select-Object -First 1
$benHit   = (Select-String -Path $ben -Pattern 'ERROR: AddressSanitizer' | Measure-Object).Count

"evil   : {0}" -f (Get-Content $evilLine.Path | Select-Object -Index ($evilLine.LineNumber - 1))
"evil   : {0}" -f $writeLine.Line.Trim()
"evil   : {0}" -f $sumLine.Line.Trim()
"benign : {0} AddressSanitizer reports" -f $benHit
""
"exit codes (same command line, same container):"
Get-Content $codes | ForEach-Object { "  $_" }
