# Bring up the local Argilla 2.8.0 stack used by this PoC:
#   1. Elasticsearch 8.11.4 container on localhost:9200 (created once, then started)
#   2. argilla-server 2.8.0 (pip wheel, bundles the production frontend) on localhost:6900
#      - SQLite database inside the package folder
#      - default owner user created via the official CLI (argilla / 1234)
# The server runs in its own console window (as a human would open a second terminal).

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here
$py = Join-Path $here ".venv\Scripts\python.exe"
# Keep the server's SQLite database inside the PoC folder instead of the user profile
$env:ARGILLA_HOME_PATH = Join-Path $here "_server_home"
# PowerShell 5.1 may route localhost HTTP through the system proxy and try ::1
# first; probe plain TCP on 127.0.0.1 instead, which cannot be proxied.
[System.Net.WebRequest]::DefaultWebProxy = $null
function Test-TcpPort([int]$port) {
    $client = New-Object Net.Sockets.TcpClient
    try {
        $client.Connect("127.0.0.1", $port)
        return $client.Connected
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}
function Wait-Port([int]$port, [string]$name, [int]$seconds) {
    foreach ($i in 1..$seconds) {
        if (Test-TcpPort $port) { Write-Host "$name is accepting connections on 127.0.0.1:$port"; return }
        Start-Sleep -Seconds 2
    }
    throw "$name did not come up on 127.0.0.1:$port"
}

Write-Host "== 1. Elasticsearch container =="
$existing = docker ps -a --filter "name=argilla-poc-es" --format "{{.Names}}"
if ($existing -eq "argilla-poc-es") {
    docker start argilla-poc-es | Out-Null
    Write-Host "started existing container argilla-poc-es"
} else {
    docker run -d --name argilla-poc-es -p 9200:9200 `
        -e discovery.type=single-node -e xpack.security.enabled=false `
        -e ES_JAVA_OPTS="-Xms512m -Xmx512m" elasticsearch:8.11.4 | Out-Null
    Write-Host "created container argilla-poc-es"
}

Write-Host "== 2. waiting for Elasticsearch on 127.0.0.1:9200 =="
Wait-Port 9200 "Elasticsearch" 120

Write-Host "== 3. database migrate + default user =="
& $py -m argilla_server database migrate
& $py -m argilla_server database users create_default

Write-Host "== 4. starting argilla-server in a separate console window =="
Start-Process -FilePath $py -ArgumentList "-m","argilla_server","start","--host","127.0.0.1","--port","6900"

Write-Host "== 5. waiting for argilla-server on 127.0.0.1:6900 =="
Wait-Port 6900 "argilla-server" 120
Write-Host "argilla-server is up: http://localhost:6900"
