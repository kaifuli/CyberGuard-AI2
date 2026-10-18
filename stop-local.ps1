$ErrorActionPreference = 'SilentlyContinue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
foreach ($name in @('web','api')) {
    $file = Join-Path $root ".run\$name.pid"
    if (Test-Path $file) {
        $processId = [int](Get-Content -LiteralPath $file -Raw)
        $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
        if ($process) {
            Stop-Process -Id $processId -Force
            Write-Host "Stopped $name process ($processId)."
        }
        Remove-Item -LiteralPath $file -Force
    }
}
Write-Host 'CyberGuard local services stopped.'
