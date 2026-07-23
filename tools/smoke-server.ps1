param(
    [int]$Port = 25631,
    [switch]$Hidden
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$env:PORT = [string]$Port
$stdout = Join-Path $root "work/server-smoke.out"
$stderr = Join-Path $root "work/server-smoke.err"
New-Item -ItemType Directory -Force -Path (Join-Path $root "work") | Out-Null

$startArgs = @{
    FilePath = "cargo"
    ArgumentList = @("run", "-p", "subconverter-server")
    WorkingDirectory = $root
    PassThru = $true
    RedirectStandardOutput = $stdout
    RedirectStandardError = $stderr
}
if ($Hidden) {
    $startArgs.WindowStyle = "Hidden"
}

$process = Start-Process @startArgs

try {
    $base = "http://127.0.0.1:$Port"
    $version = $null
    for ($i = 0; $i -lt 60; $i++) {
        Start-Sleep -Milliseconds 500
        try {
            $version = Invoke-WebRequest -UseBasicParsing -Uri "$base/version" -TimeoutSec 2
            if ($version.StatusCode -eq 200 -and $version.Content -like "*subconverter*backend*") {
                break
            }
        } catch {
            $version = $null
        }
    }
    if ($null -eq $version) {
        throw "server did not become ready on $base"
    }

    $source = [uri]::EscapeDataString("ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Smoke")
    $sub = Invoke-WebRequest -UseBasicParsing -Uri "$base/sub?target=clash&url=$source" -TimeoutSec 10
    if ($sub.StatusCode -ne 200 -or $sub.Content -notlike "*name: Smoke*" -or $sub.Content -notlike "*server: example.com*") {
        throw "sub route smoke failed"
    }

    "VERSION=$($version.Content.Trim())"
    "SUB_OK=$($sub.StatusCode)"
} finally {
    if ($process -and -not $process.HasExited) {
        Stop-Process -Id $process.Id -Force
    }
    Remove-Item Env:\PORT -ErrorAction SilentlyContinue
}
