param(
    [string[]]$Target = @()
)

$ErrorActionPreference = "Stop"

$workspace = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $workspace
try {
    if ($Target.Count -eq 0) {
        $Target = rustup target list --installed
    }

    if ($Target.Count -eq 0) {
        throw "No installed Rust targets found. Install targets with rustup target add <triple>."
    }

    foreach ($triple in $Target) {
        if ([string]::IsNullOrWhiteSpace($triple)) {
            continue
        }
        Write-Host "Checking subconverter-core for $triple"
        cargo check -p subconverter-core --target $triple
    }
}
finally {
    Pop-Location
}
