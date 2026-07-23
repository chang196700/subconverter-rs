param(
    [string]$Image = "subconverter-rs-smoke:latest",
    [string]$Name = "subconverter-rs-smoke-run",
    [int]$Port = 25641
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

docker build -t $Image $root | Out-Host
$existing = docker ps -a --filter "name=^/$Name$" --format "{{.Names}}"
if ($existing -eq $Name) {
    docker rm -f $Name | Out-Null
}
$container = docker run -d --name $Name -p "$Port`:25500" $Image

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
        throw "container did not become ready on $base"
    }

    $source = [uri]::EscapeDataString("ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#DockerSmoke")
    $sub = Invoke-WebRequest -UseBasicParsing -Uri "$base/sub?target=clash&url=$source" -TimeoutSec 10
    if ($sub.StatusCode -ne 200 -or $sub.Content -notlike "*name: DockerSmoke*" -or $sub.Content -notlike "*server: example.com*") {
        throw "container sub route smoke failed"
    }

    "CONTAINER=$container"
    "VERSION=$($version.Content.Trim())"
    "SUB_OK=$($sub.StatusCode)"
} finally {
    $existing = docker ps -a --filter "name=^/$Name$" --format "{{.Names}}"
    if ($existing -eq $Name) {
        docker rm -f $Name | Out-Null
    }
}
