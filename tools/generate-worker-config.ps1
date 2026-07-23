param(
    [string]$NamespaceId = $env:CF_KV_NAMESPACE_ID,
    [string]$Output = "work/wrangler.generated.toml",
    [string]$CustomDomain = $env:CF_CUSTOM_DOMAIN
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($NamespaceId) -or $NamespaceId -notmatch "^[0-9a-fA-F]{32}$") {
    throw "Set CF_KV_NAMESPACE_ID to a 32-character hexadecimal Cloudflare KV namespace id."
}
if (-not [string]::IsNullOrWhiteSpace($CustomDomain) -and (
        $CustomDomain -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$' -or
        $CustomDomain.Contains("..")
    )) {
    throw "CF_CUSTOM_DOMAIN must be a bare hostname such as subconv.example.com."
}

$workspace = Resolve-Path (Join-Path $PSScriptRoot "..")
$template = Join-Path $workspace "wrangler.toml"
$outputPath = Join-Path $workspace $Output
$outputDirectory = Split-Path -Parent $outputPath
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

$content = Get-Content -LiteralPath $template -Raw
$workerMain = Join-Path $workspace "crates\subconverter-worker\build\worker\shim.mjs"
$relativeMain = [IO.Path]::GetRelativePath($outputDirectory, $workerMain).Replace("\", "/")
$content = $content -replace '(?m)^main\s*=\s*"[^"]+"', "main = `"$relativeMain`""
$route = if ([string]::IsNullOrWhiteSpace($CustomDomain)) {
    ""
}
else {
    @"

[[routes]]
pattern = "$CustomDomain"
custom_domain = true
"@
}
$generated = @"
$($content.TrimEnd())

[[kv_namespaces]]
binding = "ASSETS"
id = "$NamespaceId"

[[kv_namespaces]]
binding = "CONFIG"
id = "$NamespaceId"
$route
"@

Set-Content -LiteralPath $outputPath -Value $generated -Encoding utf8NoBOM
Write-Output $outputPath
