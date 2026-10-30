param([switch]$OpenBrowser)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$apiPort = 8000
$webPort = 5173
$sqlitePath = 'data\cyberguard.sqlite3'
if (Test-Path '.env') {
    foreach ($line in Get-Content '.env') {
        if ($line -match '^\s*API_PORT\s*=\s*(\d+)') { $apiPort = [int]$Matches[1] }
        if ($line -match '^\s*VITE_PORT\s*=\s*(\d+)') { $webPort = [int]$Matches[1] }
        if ($line -match '^\s*SQLITE_PATH\s*=\s*(.*?)\s*$') { $sqlitePath = $Matches[1] }
    }
}
if ($apiPort -lt 1 -or $apiPort -gt 65535 -or $webPort -lt 1 -or $webPort -gt 65535) {
    throw 'API_PORT and VITE_PORT must be between 1 and 65535.'
}
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw 'Node.js is required. Install Node.js LTS.' }
$nodeVersion = [version](node -p "process.versions.node")
if ($nodeVersion -lt [version]'22.13.0') { throw 'Node.js 22.13 or newer is required for the built-in SQLite driver.' }
if (-not (Test-Path 'node_modules\vite\bin\vite.js')) { throw 'Frontend dependencies are missing. Run npm install first.' }

New-Item -ItemType Directory -Force -Path '.run','logs','data' | Out-Null
$apiUrl = "http://127.0.0.1:$apiPort/api/health"
$webUrl = "http://127.0.0.1:$webPort/"
$apiReady = $false
try { $null = Invoke-RestMethod -Uri $apiUrl -TimeoutSec 1; $apiReady = $true } catch {}
$apiWasAlreadyRunning = $apiReady
if (-not $apiReady) {
    $api = Start-Process -FilePath (Get-Command node).Source -ArgumentList @('server/app.js') -WorkingDirectory $root -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $root 'logs\api.log') -RedirectStandardError (Join-Path $root 'logs\api-error.log')
    Set-Content -LiteralPath '.run\api.pid' -Value $api.Id
    for ($i=0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 400
        try { $null = Invoke-RestMethod -Uri $apiUrl -TimeoutSec 1; $apiReady = $true; break } catch { if ($api.HasExited) { break } }
    }
}
if (-not $apiReady) {
    if (Test-Path 'logs\api-error.log') { Get-Content 'logs\api-error.log' -Tail 15 }
    throw "Local API did not become ready at $apiUrl. See logs\api-error.log."
}

$webReady = $false
try { $null = Invoke-WebRequest -Uri $webUrl -TimeoutSec 1 -UseBasicParsing; $webReady = $true } catch {}
$webWasAlreadyRunning = $webReady
if (-not $webReady) {
    $node = (Get-Command node).Source
    $vite = Join-Path $root 'node_modules\vite\bin\vite.js'
    $web = Start-Process -FilePath $node -ArgumentList @($vite,'--host','127.0.0.1','--port',"$webPort",'--strictPort') -WorkingDirectory $root -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $root 'logs\web.log') -RedirectStandardError (Join-Path $root 'logs\web-error.log')
    Set-Content -LiteralPath '.run\web.pid' -Value $web.Id
    for ($i=0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 400
        try { $null = Invoke-WebRequest -Uri $webUrl -TimeoutSec 1 -UseBasicParsing; $webReady = $true; break } catch { if ($web.HasExited) { break } }
    }
}
if (-not $webReady) {
    if (Test-Path 'logs\web-error.log') { Get-Content 'logs\web-error.log' -Tail 15 }
    throw "Frontend did not become ready at $webUrl. See logs\web-error.log."
}
Write-Host "CyberGuard AI is ready at $webUrl" -ForegroundColor Green
Write-Host "API: $apiUrl   (bound to 127.0.0.1)"
if ([IO.Path]::IsPathRooted($sqlitePath)) { $resolvedDbPath = $sqlitePath } else { $resolvedDbPath = Join-Path $root $sqlitePath }
Write-Host "SQLite: $resolvedDbPath"
if ($apiWasAlreadyRunning -or $webWasAlreadyRunning) { Write-Host 'One or more services were already running. .\stop-local.ps1 stops only instances this script started; stop pre-existing services in their original terminal.' }
else { Write-Host 'Stop both services with: .\stop-local.ps1' }
if ($OpenBrowser) { Start-Process $webUrl }

