param(
    [string]$NamespaceId = $env:CF_KV_NAMESPACE_ID,
    [string]$Output = "work/wrangler.generated.toml"
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($NamespaceId) -or $NamespaceId -notmatch "^[0-9a-fA-F]{32}$") {
    throw "Set CF_KV_NAMESPACE_ID to a 32-character hexadecimal Cloudflare KV namespace id."
}

$workspace = Resolve-Path (Join-Path $PSScriptRoot "..")
$template = Join-Path $workspace "wrangler.toml"
$outputPath = Join-Path $workspace $Output
$outputDirectory = Split-Path -Parent $outputPath
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

$content = Get-Content -LiteralPath $template -Raw
$generated = @"
$($content.TrimEnd())

[[kv_namespaces]]
binding = "ASSETS"
id = "$NamespaceId"

[[kv_namespaces]]
binding = "CONFIG"
id = "$NamespaceId"
"@

Set-Content -LiteralPath $outputPath -Value $generated -Encoding utf8NoBOM
Write-Output $outputPath
