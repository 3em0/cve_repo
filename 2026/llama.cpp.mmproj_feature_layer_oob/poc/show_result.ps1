# Summarise the verdict-bearing fields of exp/drive.py's result.json.
# Used as the final evidence line of the bug-1 reproduction run.
#
#   .\poc\show_result.ps1 out\result.json
param(
    [Parameter(Mandatory = $true)][string]$ResultJson
)

$r = Get-Content -Raw $ResultJson | ConvertFrom-Json

"root_key                 : {0}" -f $r.root_key
"pinned_commit            : {0} (matches expected: {1})" -f $r.product.pinned_commit, $r.product.pinned_commit_matches_expected
"artifact_hashes_match    : {0}" -f $r.artifact_sha256_matches_expected
""
"positive  (mmproj_evil.gguf)   exit_code={0}  asan_reports={1}" -f $r.positive.exit_code, $r.positive.asan_error_reports
"negative  (mmproj_benign.gguf) exit_code={0}  asan_reports={1}" -f $r.negative_control.exit_code, $r.negative_control.asan_error_reports
""
if ($r.positive.signature) {
    "asan error      : {0}" -f $r.positive.signature.error
    "asan access     : {0} of size {1} bytes" -f $r.positive.signature.access, $r.positive.signature.access_size
    "top frame       : {0}" -f $r.positive.signature.frames[0]
}

# The region line is read straight from the sanitizer report: drive.py's normaliser
# only fills distance_bytes/direction when the toolchain phrases the location as
# "N bytes to the right of", which clang 16 does not.
$asanFile = Join-Path $PSScriptRoot 'out\logs\asan.evil.0.txt'
if (Test-Path $asanFile) {
    $loc = Select-String -Path $asanFile -Pattern 'is located' | Select-Object -First 1
    if ($loc) { "region          : {0}" -f $loc.Line.Trim() }
}
""
"verdict          : {0}" -f $r.verdict
"canary_hit       : {0}" -f $r.canary_hit
"negctl_clean     : {0}" -f $r.negative_control_clean
