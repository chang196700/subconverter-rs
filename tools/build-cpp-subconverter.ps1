param(
    [string]$SourceRoot = "",
    [string]$BuildDir = "build-codex-msys",
    [string]$Generator = "Ninja",
    [switch]$PreferMsys2,
    [switch]$InstallMsys2Deps
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($SourceRoot)) {
    if (-not [string]::IsNullOrWhiteSpace($env:SUBCONVERTER_CPP_SOURCE)) {
        $SourceRoot = $env:SUBCONVERTER_CPP_SOURCE
    } else {
        $SourceRoot = Join-Path $PSScriptRoot "..\work\baseline\subconverter-source"
    }
}
$SourceRoot = [IO.Path]::GetFullPath($SourceRoot)

if (-not (Test-Path -LiteralPath $SourceRoot)) {
    throw "source root not found: $SourceRoot"
}

$existing = Get-ChildItem -LiteralPath $SourceRoot -Recurse -Filter subconverter.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch "\\$BuildDir\\CMakeFiles\\" } |
    Select-Object -First 1
if ($existing) {
    Write-Host "found existing executable: $($existing.FullName)"
    return
}

$cmake = Get-Command cmake -ErrorAction SilentlyContinue
if (-not $cmake) {
    throw "cmake not found in PATH"
}

$ninja = Get-Command ninja -ErrorAction SilentlyContinue
if ($Generator -eq "Ninja" -and -not $ninja) {
    throw "ninja not found in PATH"
}

$cmakeArgs = @(
    "-S", ".",
    "-B", $BuildDir,
    "-G", $Generator,
    "-DCMAKE_BUILD_TYPE=Release"
)

$msysRoot = "C:\msys64"
$msysMingw = Join-Path $msysRoot "mingw64"
$msysBin = Join-Path $msysMingw "bin"
$msysUsrBin = Join-Path $msysRoot "usr\bin"

if ($PreferMsys2 -or (Test-Path -LiteralPath $msysBin)) {
    $env:PATH = "$msysBin;$msysUsrBin;$env:PATH"
    $pkgConfig = Join-Path $msysBin "pkg-config.exe"
    if (-not (Test-Path -LiteralPath $pkgConfig)) {
        $pkgConfig = Join-Path $msysUsrBin "pkg-config.exe"
    }
    if (Test-Path -LiteralPath $pkgConfig) {
        $cmakeArgs += "-DPKG_CONFIG_EXECUTABLE=$pkgConfig"
    }
    $cmakeArgs += "-DCMAKE_PREFIX_PATH=$msysMingw"
    $cmakeArgs += "-DCMAKE_C_COMPILER=$(Join-Path $msysBin 'gcc.exe')"
    $cmakeArgs += "-DCMAKE_CXX_COMPILER=$(Join-Path $msysBin 'g++.exe')"

    if ($InstallMsys2Deps) {
        $pacman = Join-Path $msysUsrBin "pacman.exe"
        if (-not (Test-Path -LiteralPath $pacman)) {
            throw "MSYS2 pacman not found: $pacman"
        }
        & $pacman -Sy --noconfirm
        & $pacman -S --needed --noconfirm `
            mingw-w64-x86_64-pkgconf `
            mingw-w64-x86_64-curl `
            mingw-w64-x86_64-yaml-cpp `
            mingw-w64-x86_64-pcre2 `
            mingw-w64-x86_64-rapidjson
    }
} else {
    $pkgConfig = Get-Command pkg-config -ErrorAction SilentlyContinue
    if ($pkgConfig) {
        $cmakeArgs += "-DPKG_CONFIG_EXECUTABLE=$($pkgConfig.Source)"
    }
}

Push-Location $SourceRoot
try {
    Write-Host "configuring C++ subconverter..."
    & $cmake.Source @cmakeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "cmake configure failed. Install native dependencies: libcurl, rapidjson, toml11, yaml-cpp, pcre2, quickjs, libcron."
    }

    Write-Host "building C++ subconverter..."
    & $cmake.Source --build $BuildDir --config Release
    if ($LASTEXITCODE -ne 0) {
        throw "cmake build failed"
    }
} finally {
    Pop-Location
}

$built = Get-ChildItem -LiteralPath (Join-Path $SourceRoot $BuildDir) -Recurse -Filter subconverter.exe -ErrorAction SilentlyContinue |
    Select-Object -First 1
if (-not $built) {
    throw "build completed but subconverter.exe was not found under $BuildDir"
}

Write-Host "built executable: $($built.FullName)"
