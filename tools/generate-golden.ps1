param(
    [string]$SubconverterExe = "",
    [string]$BaseUrl = "",
    [string]$Fixtures = "tests\fixtures",
    [string]$Manifest = "cases.toml",
    [string]$Reference = "tests\fixtures\reference.toml",
    [int]$Port = 25580,
    [int]$FixturePort = 25579,
    [string]$FixtureBaseUrl = "",
    [switch]$NoFixtureServer,
    [switch]$InlineInput,
    [switch]$Hidden,
    [switch]$ValidateOnly
)

$ErrorActionPreference = "Stop"

$fixtureRoot = Resolve-Path -LiteralPath $Fixtures
$manifestPath = Join-Path $fixtureRoot $Manifest
$referencePath = Resolve-Path -LiteralPath $Reference
$workspaceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "manifest not found: $manifestPath"
}

$referenceContent = Get-Content -LiteralPath $referencePath -Raw
function Get-ReferenceValue {
    param(
        [string]$Content,
        [string]$Section,
        [string]$Key
    )

    $inSection = [string]::IsNullOrWhiteSpace($Section)
    foreach ($line in $Content -split "`r?`n") {
        $trimmed = $line.Trim()
        if ($trimmed -match '^\[([^\]]+)\]$') {
            $inSection = $matches[1] -eq $Section
            continue
        }
        if ($inSection -and $trimmed -match "^$([regex]::Escape($Key))\s*=\s*`"(.*)`"\s*$") {
            return $matches[1]
        }
    }
    throw "reference key not found: [$Section] $Key"
}

$referenceRelease = Get-ReferenceValue -Content $referenceContent -Section "" -Key "release"
$referenceCommit = Get-ReferenceValue -Content $referenceContent -Section "" -Key "commit"
$referenceWindowsPath = Get-ReferenceValue -Content $referenceContent -Section "windows" -Key "path"
$referenceWindowsHash = Get-ReferenceValue -Content $referenceContent -Section "windows" -Key "sha256"
if (-not [IO.Path]::IsPathRooted($referenceWindowsPath)) {
    $referenceWindowsPath = [IO.Path]::GetFullPath((Join-Path $workspaceRoot $referenceWindowsPath))
}
if ([string]::IsNullOrWhiteSpace($SubconverterExe)) {
    $SubconverterExe = $referenceWindowsPath
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw
$cases = @()
$current = $null
foreach ($line in $manifest -split "`r?`n") {
    $trimmed = $line.Trim()
    if ($trimmed -eq "[[case]]") {
        if ($current) { $cases += $current }
        $current = @{}
        continue
    }
    if (-not $current -or $trimmed.Length -eq 0 -or $trimmed.StartsWith("#")) {
        continue
    }
    if ($trimmed -match '^([A-Za-z0-9_]+)\s*=\s*"(.*)"\s*$') {
        $current[$matches[1]] = $matches[2]
    } elseif ($trimmed -match '^([A-Za-z0-9_]+)\s*=\s*([0-9]+)\s*$') {
        $current[$matches[1]] = [int]$matches[2]
    }
}
if ($current) { $cases += $current }

if ($cases.Count -eq 0) {
    throw "No cases found in $manifestPath"
}

if ($ValidateOnly) {
    foreach ($case in $cases) {
        $inputPath = Join-Path $fixtureRoot $case["input"]
        if (-not (Test-Path -LiteralPath $inputPath)) {
            throw "input fixture not found for $($case["name"]): $inputPath"
        }
        if ($case.ContainsKey("config")) {
            $configPath = Join-Path $fixtureRoot $case["config"]
            if (-not (Test-Path -LiteralPath $configPath)) {
                throw "config fixture not found for $($case["name"]): $configPath"
            }
        }
        $goldenPath = Join-Path $fixtureRoot $case["golden"]
        if (-not (Test-Path -LiteralPath $goldenPath -PathType Leaf)) {
            throw "golden fixture not found for $($case["name"]): $goldenPath"
        }
        Write-Host "case $($case["name"]) target=$($case["target"]) golden=$($case["golden"])"
    }
    Write-Host "validated $($cases.Count) cases from $manifestPath against $referenceRelease ($referenceCommit)"
    return
}

function Start-FixtureServer {
    param(
        [string]$Root,
        [int]$ListenPort
    )

    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        $python = Get-Command python3 -ErrorAction SilentlyContinue
    }
    if (-not $python) {
        throw "Python is required to serve non-inline golden fixtures."
    }
    $startArgs = @{
        FilePath = $python.Source
        ArgumentList = @("-m", "http.server", [string]$ListenPort, "--bind", "127.0.0.1", "--directory", $Root)
        PassThru = $true
    }
    if ($IsWindows) {
        $startArgs.WindowStyle = "Hidden"
    }
    $process = Start-Process @startArgs

    for ($i = 0; $i -lt 40; $i++) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:$ListenPort/" | Out-Null
            return $process
        } catch {
            if ($process.HasExited) {
                throw "fixture server failed to start on port $ListenPort"
            }
            Start-Sleep -Milliseconds 250
        }
    }
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    throw "fixture server did not start on port $ListenPort"
}

$process = $null
$fixtureServer = $null
$referenceRuntime = $null
$serverUrl = $BaseUrl.TrimEnd("/")
$usingLocalReference = [string]::IsNullOrWhiteSpace($serverUrl)
$fixtureUrl = $FixtureBaseUrl.TrimEnd("/")
if ($NoFixtureServer -and [string]::IsNullOrWhiteSpace($fixtureUrl)) {
    throw "-NoFixtureServer requires -FixtureBaseUrl"
}
if ([string]::IsNullOrWhiteSpace($fixtureUrl)) {
    $fixtureUrl = "http://127.0.0.1:$FixturePort"
}
if ([string]::IsNullOrWhiteSpace($serverUrl)) {
    if (-not (Test-Path -LiteralPath $SubconverterExe)) {
        throw "C++ subconverter executable not found: $SubconverterExe"
    }

    $actualHash = (Get-FileHash -LiteralPath $SubconverterExe -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $referenceWindowsHash.ToLowerInvariant()) {
        throw "C++ reference hash mismatch: expected $referenceWindowsHash, got $actualHash"
    }

    $referenceRuntime = [IO.Path]::GetFullPath((Join-Path $workspaceRoot "work\reference-v0.9.0"))
    $workRoot = [IO.Path]::GetFullPath((Join-Path $workspaceRoot "work"))
    if (-not $referenceRuntime.StartsWith($workRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "reference runtime escaped work directory: $referenceRuntime"
    }
    if (Test-Path -LiteralPath $referenceRuntime) {
        Remove-Item -LiteralPath $referenceRuntime -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $referenceRuntime | Out-Null
    $releaseRoot = Split-Path -Parent $SubconverterExe
    Copy-Item -LiteralPath (Join-Path $releaseRoot "base") -Destination (Join-Path $referenceRuntime "base") -Recurse
    Copy-Item -LiteralPath $SubconverterExe -Destination (Join-Path $referenceRuntime "subconverter.exe")
    Copy-Item -LiteralPath (Join-Path $fixtureRoot "reference\pref.ini") -Destination (Join-Path $referenceRuntime "pref.ini")
    $referenceFixtures = Join-Path $referenceRuntime "base\reference-fixtures"
    New-Item -ItemType Directory -Force -Path $referenceFixtures | Out-Null
    foreach ($case in $cases) {
        foreach ($field in @("input", "config")) {
            if (-not $case.ContainsKey($field)) {
                continue
            }
            $relative = $case[$field].Replace("/", [IO.Path]::DirectorySeparatorChar)
            $source = Join-Path $fixtureRoot $relative
            $destination = Join-Path $referenceFixtures $relative
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
            Copy-Item -LiteralPath $source -Destination $destination
        }
    }

    $workDir = $referenceRuntime
    $runtimeExe = Join-Path $referenceRuntime "subconverter.exe"
    $env:PORT = [string]$Port
    $serverUrl = "http://127.0.0.1:$Port"
    $startArgs = @{
        FilePath = $runtimeExe
        WorkingDirectory = $workDir
        PassThru = $true
    }
    if ($Hidden) {
        $startArgs.WindowStyle = "Hidden"
    }
}
if (-not $NoFixtureServer -and -not $InlineInput) {
    $fixtureServer = Start-FixtureServer -Root $fixtureRoot.Path -ListenPort $FixturePort
}
if (-not [string]::IsNullOrWhiteSpace($BaseUrl)) {
    Write-Host "using existing C++ subconverter server at $serverUrl"
} else {
    $process = Start-Process @startArgs
}
try {
    $ready = $false
    for ($i = 0; $i -lt 40; $i++) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "$serverUrl/version" | Out-Null
            $ready = $true
            break
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    if (-not $ready) {
        throw "C++ subconverter did not start on port $Port"
    }

    foreach ($case in $cases) {
        $goldenPath = Join-Path $fixtureRoot $case["golden"]
        $target = [uri]::EscapeDataString($case["target"])
        if ($InlineInput) {
            $inputPath = Join-Path $fixtureRoot $case["input"]
            $url = (Get-Content -LiteralPath $inputPath -Raw).Trim()
        } else {
            $url = "$fixtureUrl/$($case["input"].Replace('\', '/'))"
        }
        $requestUrl = "$serverUrl/sub?target=$target&url=$([uri]::EscapeDataString($url))"
        if ($case.ContainsKey("config")) {
            if ($InlineInput -and $usingLocalReference) {
                $config = "base/reference-fixtures/$($case["config"].Replace('\', '/'))"
            } else {
                $config = "$fixtureUrl/$($case["config"].Replace('\', '/'))"
            }
            $requestUrl += "&config=$([uri]::EscapeDataString($config))"
        }
        if ($case.ContainsKey("surge_version")) {
            $requestUrl += "&ver=$($case["surge_version"])"
        }
        $response = Invoke-WebRequest -UseBasicParsing -Uri $requestUrl
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $goldenPath) | Out-Null
        Set-Content -LiteralPath $goldenPath -Value $response.Content -NoNewline
        Write-Host "generated $($case["name"]) -> $goldenPath"
    }
} finally {
    if ($process) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    }
    if ($fixtureServer) {
        Stop-Process -Id $fixtureServer.Id -Force -ErrorAction SilentlyContinue
    }
    if ($referenceRuntime -and (Test-Path -LiteralPath $referenceRuntime)) {
        Remove-Item -LiteralPath $referenceRuntime -Recurse -Force
    }
}
