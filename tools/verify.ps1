param(
    [switch]$SkipContainer,
    [switch]$SkipServerSmoke,
    [string[]]$CoreTarget = @()
)

$ErrorActionPreference = "Stop"

$workspace = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $workspace
try {
    Write-Host "== format =="
    cargo fmt --all -- --check

    Write-Host "== workspace check =="
    cargo check --workspace

    Write-Host "== clippy =="
    cargo clippy --workspace --all-targets -- -D warnings

    Write-Host "== workspace tests =="
    cargo test --workspace

    Write-Host "== golden manifest =="
    & (Join-Path $PSScriptRoot "generate-golden.ps1") -Manifest cases.full.toml -ValidateOnly
    if (Select-String -LiteralPath "wrangler.toml" -Pattern "replace-with|placeholder" -Quiet) {
        throw "wrangler.toml contains a deployable placeholder namespace id"
    }

    Write-Host "== core std targets =="
    if ($CoreTarget.Count -gt 0) {
        & (Join-Path $PSScriptRoot "check-core-std-targets.ps1") -Target $CoreTarget
    } else {
        & (Join-Path $PSScriptRoot "check-core-std-targets.ps1")
    }

    Write-Host "== cloudflare worker check =="
    cargo check -p subconverter-worker --target wasm32-unknown-unknown --features cloudflare

    if (-not $SkipServerSmoke) {
        Write-Host "== server smoke =="
        & (Join-Path $PSScriptRoot "smoke-server.ps1")
    }

    if (-not $SkipContainer) {
        Write-Host "== container smoke =="
        & (Join-Path $PSScriptRoot "smoke-container.ps1")
    }
}
finally {
    Pop-Location
}
