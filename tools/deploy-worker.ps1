param(
    [string]$NamespaceId = $env:CF_KV_NAMESPACE_ID
)

$ErrorActionPreference = "Stop"
$workspace = Resolve-Path (Join-Path $PSScriptRoot "..")
$config = & (Join-Path $PSScriptRoot "generate-worker-config.ps1") -NamespaceId $NamespaceId

Push-Location $workspace
try {
    npx wrangler deploy --config $config
}
finally {
    Pop-Location
}
