param(
    [ValidateSet("system", "user")]
    [string]$Scope = "system",
    [string]$Binary,
    [string]$AssetDir,
    [switch]$KeepData
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $Binary) {
    $name = if ($IsWindows -or $env:OS -eq "Windows_NT") {
        "subconverter-server.exe"
    } else {
        "subconverter-server"
    }
    $Binary = Join-Path $root "target/release/$name"
}
$Binary = (Resolve-Path $Binary).Path
if (-not $AssetDir) {
    $AssetDir = $root
}
$AssetDir = (Resolve-Path $AssetDir).Path
$workRoot = Join-Path $root "work"
New-Item -ItemType Directory -Force -Path $workRoot | Out-Null
$isWindowsHost = $IsWindows -or $env:OS -eq "Windows_NT"
$smokeId = [guid]::NewGuid().ToString("N")
if ($Scope -eq "system") {
    if ($isWindowsHost) {
        $cleanupRoot = $env:ProgramData
    } elseif ($IsMacOS) {
        $cleanupRoot = "/Library/Application Support"
    } else {
        $cleanupRoot = "/var/lib"
    }
    $dataDir = Join-Path $cleanupRoot "subconverter-rs-smoke-$smokeId"
} else {
    $cleanupRoot = $workRoot
    $dataDir = Join-Path $workRoot "service-smoke-user-$smokeId"
}

if ($Scope -eq "system") {
    if ($isWindowsHost) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw "system service smoke must run from an elevated shell"
        }
    } elseif ((& id -u) -ne "0") {
        throw "system service smoke must run as root"
    }
}

function Invoke-ServiceCommand {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments,
        [int[]]$ExpectedExit = @(0)
    )
    $output = & $Binary @Arguments 2>&1
    $code = $LASTEXITCODE
    if ($ExpectedExit -notcontains $code) {
        throw "'$Binary $($Arguments -join ' ')' exited $code`: $($output -join [Environment]::NewLine)"
    }
    return @{
        Code = $code
        Output = ($output -join [Environment]::NewLine).Trim()
    }
}

function Wait-ServiceStatus {
    param(
        [Parameter(Mandatory)]
        [string]$Expected,
        [int]$ExpectedExit
    )
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $status = Invoke-ServiceCommand -Arguments @("service", "status", "--scope", $Scope) -ExpectedExit @(0, 3, 4)
        if ($status.Code -eq $ExpectedExit -and $status.Output -eq $Expected) {
            return
        }
        Start-Sleep -Milliseconds 500
    }
    throw "service did not reach $Expected"
}

$installed = $false
try {
    if ($isWindowsHost) {
        $unsupported = Invoke-ServiceCommand -Arguments @("service", "status", "--scope", "user") -ExpectedExit @(1)
        if ($unsupported.Output -notlike "*does not support --scope user*") {
            throw "Windows user-scope error contract changed: $($unsupported.Output)"
        }
        if ($Scope -eq "user") {
            "WINDOWS_USER_SCOPE_UNSUPPORTED=ok"
            return
        }
    }

    Invoke-ServiceCommand -Arguments @(
        "service", "install",
        "--scope", $Scope,
        "--data-dir", $dataDir,
        "--asset-dir", $AssetDir
    ) | Out-Null
    $installed = $true
    Wait-ServiceStatus -Expected "running" -ExpectedExit 0

    $version = $null
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        try {
            $version = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:25500/version" -TimeoutSec 2
            if ($version.StatusCode -eq 200) {
                break
            }
        } catch {
            $version = $null
        }
        Start-Sleep -Milliseconds 500
    }
    if ($null -eq $version -or $version.Content -notlike "*subconverter*backend*") {
        throw "managed service /version check failed"
    }

    Invoke-ServiceCommand -Arguments @("service", "restart", "--scope", $Scope) | Out-Null
    Wait-ServiceStatus -Expected "running" -ExpectedExit 0
    Invoke-ServiceCommand -Arguments @("service", "stop", "--scope", $Scope) | Out-Null
    Wait-ServiceStatus -Expected "stopped" -ExpectedExit 3
    Invoke-ServiceCommand -Arguments @("service", "uninstall", "--scope", $Scope) | Out-Null
    $installed = $false
    Wait-ServiceStatus -Expected "not-installed" -ExpectedExit 4

    $portClosed = $false
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:25500/version" -TimeoutSec 1 | Out-Null
            Start-Sleep -Milliseconds 250
        } catch {
            $portClosed = $true
            break
        }
    }
    if (-not $portClosed) {
        throw "service process still responds after uninstall"
    }
    if (-not (Test-Path (Join-Path $dataDir "pref.toml"))) {
        throw "uninstall unexpectedly removed persistent data"
    }
    "SERVICE_SMOKE_OK scope=$Scope version=$($version.Content.Trim())"
} finally {
    if ($installed) {
        try {
            Invoke-ServiceCommand -Arguments @("service", "uninstall", "--scope", $Scope) -ExpectedExit @(0, 1) | Out-Null
        } catch {
            Write-Warning "service cleanup failed: $_"
        }
    }
    if (-not $KeepData -and (Test-Path -LiteralPath $dataDir)) {
        $resolvedData = (Resolve-Path -LiteralPath $dataDir).Path
        $resolvedCleanupRoot = (Resolve-Path -LiteralPath $cleanupRoot).Path
        $leaf = Split-Path -Leaf $resolvedData
        if (
            -not $resolvedData.StartsWith($resolvedCleanupRoot + [IO.Path]::DirectorySeparatorChar) -or
            ($leaf -notlike "*service-smoke*" -and $leaf -notlike "subconverter-rs-smoke-*")
        ) {
            throw "refusing to remove unexpected service smoke data: $resolvedData"
        }
        Remove-Item -LiteralPath $resolvedData -Recurse -Force
    }
}
