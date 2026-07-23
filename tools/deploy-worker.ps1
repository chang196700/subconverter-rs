param(
    [string]$NamespaceId = $env:CF_KV_NAMESPACE_ID,
    [string]$CustomDomain = $env:CF_CUSTOM_DOMAIN,
    [string]$UpstreamUserAgent = $env:CF_UPSTREAM_USER_AGENT
)

$ErrorActionPreference = "Stop"
$workspace = Resolve-Path (Join-Path $PSScriptRoot "..")
$config = & (Join-Path $PSScriptRoot "generate-worker-config.ps1") `
    -NamespaceId $NamespaceId `
    -CustomDomain $CustomDomain `
    -UpstreamUserAgent $UpstreamUserAgent

Push-Location $workspace
try {
    npx wrangler deploy --config $config
}
finally {
    Pop-Location
}
