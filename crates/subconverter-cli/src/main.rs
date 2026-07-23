use std::fs;
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use clap::Parser;
use subconverter_core::{
    expand_imports_with, handle_request, AdapterCapabilities, ConfigFormat, CoreRequest, Error,
    FetchRequest, FetchedContent, Method, PlatformIo, Settings, SurgeVersion,
};
#[cfg(test)]
use subconverter_core::{model::RegexMatchConfig, ConvertOptions, TriBool};

#[derive(Debug, Parser)]
#[command(name = "subconverter")]
#[command(about = "Rust subconverter CLI compatibility entrypoint")]
struct Args {
    #[arg(short = 'f', long = "file")]
    pref: Option<PathBuf>,
    #[arg(short = 'g', long = "gen")]
    generator_mode: bool,
    #[arg(long = "artifact")]
    artifact: Option<String>,
    #[arg(short = 'l', long = "log")]
    log: Option<PathBuf>,
    #[arg(long)]
    target: Option<String>,
    #[arg(long)]
    url: Option<String>,
    #[arg(long)]
    config: Option<String>,
    #[arg(long)]
    include: Option<String>,
    #[arg(long)]
    exclude: Option<String>,
    #[arg(long)]
    group: Option<String>,
    #[arg(long)]
    rename: Vec<String>,
    #[arg(long = "append-type", alias = "append_type")]
    append_type: Option<String>,
    #[arg(long)]
    sort: Option<String>,
    #[arg(long)]
    udp: Option<String>,
    #[arg(long)]
    tfo: Option<String>,
    #[arg(long, alias = "skip-cert-verify")]
    scv: Option<String>,
    #[arg(long)]
    tls13: Option<String>,
    #[arg(long = "list")]
    nodelist: Option<String>,
    #[arg(long)]
    fdn: Option<String>,
    #[arg(long)]
    expand: Option<String>,
    #[arg(long)]
    classic: Option<String>,
    #[arg(long = "ver", alias = "surge-version")]
    surge_version: Option<SurgeVersion>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let (settings, pref_content) = load_settings(args.pref.as_ref())?;

    if args.generator_mode || args.target.is_some() || args.url.is_some() {
        run_conversion_mode(&args, settings, pref_content).await?;
        return Ok(());
    }

    println!(
        "subconverter v{} backend; pref listen={}:{}",
        subconverter_core::VERSION,
        settings.listen,
        settings.port
    );

    Ok(())
}

async fn run_conversion_mode(
    args: &Args,
    settings: Settings,
    _pref_content: Option<String>,
) -> Result<()> {
    let Some(source) = args.url.as_deref() else {
        println!(
            "generator mode initialized; artifact={}",
            args.artifact.as_deref().unwrap_or("")
        );
        return Ok(());
    };
    let io = CliIo;
    if let Some(log) = args.log.as_ref() {
        write_log(
            log,
            &format!("sources=1 generator={}\n", args.generator_mode),
        )?;
    }

    if let Some(target) = args.target.as_deref() {
        let output = convert_through_core(&io, &settings, args, source, target).await?;
        emit_artifact(args.artifact.as_deref(), target, &output, false)?;
        return Ok(());
    }

    let targets = generator_targets();
    let mut rendered = Vec::new();
    for target in targets {
        let output = convert_through_core(&io, &settings, args, source, target).await?;
        emit_artifact(args.artifact.as_deref(), target, &output, true)?;
        rendered.push((target, output));
    }
    if args.artifact.is_none() {
        for (target, output) in rendered {
            println!("===== {target} =====");
            println!("{output}");
        }
    }
    Ok(())
}

async fn convert_through_core(
    io: &CliIo,
    settings: &Settings,
    args: &Args,
    source: &str,
    target: &str,
) -> Result<String> {
    let mut query = vec![("target", target.to_string()), ("url", source.to_string())];
    if let Some(config) = &args.config {
        query.push(("config", config.clone()));
    }
    push_arg(&mut query, "include", args.include.as_deref());
    push_arg(&mut query, "exclude", args.exclude.as_deref());
    push_arg(&mut query, "group", args.group.as_deref());
    if !args.rename.is_empty() {
        query.push(("rename", args.rename.join("`")));
    }
    push_arg(&mut query, "append_type", args.append_type.as_deref());
    push_arg(&mut query, "sort", args.sort.as_deref());
    push_arg(&mut query, "udp", args.udp.as_deref());
    push_arg(&mut query, "tfo", args.tfo.as_deref());
    push_arg(&mut query, "scv", args.scv.as_deref());
    push_arg(&mut query, "tls13", args.tls13.as_deref());
    push_arg(&mut query, "list", args.nodelist.as_deref());
    push_arg(&mut query, "fdn", args.fdn.as_deref());
    push_arg(&mut query, "expand", args.expand.as_deref());
    push_arg(&mut query, "classic", args.classic.as_deref());
    if let Some(version) = args.surge_version {
        query.push(("ver", version.to_string()));
    }
    let query = query
        .into_iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                subconverter_core::util::url_encode(key),
                subconverter_core::util::url_encode(&value)
            )
        })
        .collect::<Vec<_>>()
        .join("&");
    let mut runtime_settings = settings.clone();
    let response = handle_request(
        io,
        &mut runtime_settings,
        CoreRequest {
            method: Method::Get,
            path: "/sub".to_string(),
            query,
            body: String::new(),
            headers: Default::default(),
        },
    )
    .await;
    if response.status >= 400 {
        anyhow::bail!(
            "conversion failed with HTTP {}: {}",
            response.status,
            response.body.trim()
        );
    }
    Ok(response.body)
}

fn push_arg(query: &mut Vec<(&'static str, String)>, key: &'static str, value: Option<&str>) {
    if let Some(value) = value {
        query.push((key, value.to_string()));
    }
}

#[cfg(test)]
fn convert_options_from_args(args: &Args) -> ConvertOptions {
    ConvertOptions {
        include_remarks: split_patterns(args.include.as_deref()),
        exclude_remarks: split_patterns(args.exclude.as_deref()),
        node_group: args
            .group
            .as_ref()
            .filter(|value| !value.is_empty())
            .cloned(),
        rename_node: args
            .rename
            .iter()
            .filter_map(|value| parse_rename(value))
            .collect(),
        append_proxy_type: parse_tribool(args.append_type.as_deref()),
        sort: parse_tribool(args.sort.as_deref()),
        udp: parse_tribool(args.udp.as_deref()),
        tcp_fast_open: parse_tribool(args.tfo.as_deref()),
        skip_cert_verify: parse_tribool(args.scv.as_deref()),
        tls13: parse_tribool(args.tls13.as_deref()),
        nodelist: parse_tribool(args.nodelist.as_deref()),
        filter_deprecated: parse_tribool(args.fdn.as_deref()),
        expand_rulesets: parse_tribool(args.expand.as_deref()),
        classic_ruleset: parse_tribool(args.classic.as_deref()),
        ..ConvertOptions::default()
    }
}

#[cfg(test)]
fn split_patterns(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or("")
        .split(['|', ','])
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(test)]
fn parse_rename(value: &str) -> Option<RegexMatchConfig> {
    let (r#match, replace) = value.split_once('@')?;
    Some(RegexMatchConfig {
        script: None,
        r#match: r#match.trim().to_string(),
        replace: replace.trim().to_string(),
    })
}

#[cfg(test)]
fn parse_tribool(value: Option<&str>) -> TriBool {
    value.map(TriBool::parse).unwrap_or_default()
}

fn load_settings(path: Option<&PathBuf>) -> Result<(Settings, Option<String>)> {
    let Some(path) = path else {
        return Ok((Settings::default(), None));
    };
    let content = read_config_file(path)?;
    let format = match path.extension().and_then(|ext| ext.to_str()) {
        Some("toml") => ConfigFormat::Toml,
        Some("yml" | "yaml") => ConfigFormat::Yaml,
        _ => ConfigFormat::Ini,
    };
    Ok((Settings::parse(&content, format)?, Some(content)))
}

fn read_config_file(path: &Path) -> Result<String> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    let base_dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
    expand_imports_with(&content, |import| {
        let import_path = Path::new(import);
        let path = if import_path.is_absolute() {
            import_path.to_path_buf()
        } else {
            base_dir.join(import_path)
        };
        fs::read_to_string(&path)
            .map_err(|err| subconverter_core::Error::Io(format!("{}: {err}", path.display())))
    })
    .map_err(Into::into)
}

#[derive(Debug, Clone)]
struct CliIo;

impl Default for CliIo {
    fn default() -> Self {
        Self
    }
}

#[async_trait]
impl PlatformIo for CliIo {
    async fn fetch_url(&self, url: &str) -> subconverter_core::Result<String> {
        Ok(self.fetch(&FetchRequest::new(url)).await?.body)
    }

    async fn fetch(&self, request: &FetchRequest) -> subconverter_core::Result<FetchedContent> {
        let mut current = reqwest::Url::parse(&request.url)
            .map_err(|err| Error::Forbidden(format!("invalid URL: {err}")))?;
        for redirect_count in 0..=request.max_redirects {
            validate_cli_url(&current, request)?;
            let host = current
                .host_str()
                .ok_or_else(|| Error::Forbidden("upstream URL has no host".to_string()))?;
            let port = current
                .port_or_known_default()
                .ok_or_else(|| Error::Forbidden("upstream URL has no port".to_string()))?;
            let addresses = tokio::net::lookup_host((host, port))
                .await
                .map_err(|err| Error::Upstream(format!("DNS resolution failed: {err}")))?
                .collect::<Vec<_>>();
            if addresses.is_empty() {
                return Err(Error::Upstream(format!(
                    "DNS resolution returned no addresses for {host}"
                )));
            }
            if !request.allow_private_network
                && addresses
                    .iter()
                    .any(|address| is_non_public_ip(address.ip()))
            {
                return Err(Error::Forbidden(format!(
                    "DNS resolved {host} to a non-public address"
                )));
            }
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(request.connect_timeout_seconds))
                .timeout(Duration::from_secs(request.request_timeout_seconds))
                .resolve_to_addrs(host, &addresses)
                .build()
                .map_err(|err| Error::Io(err.to_string()))?;
            let mut outgoing = client.get(current.clone());
            for (key, value) in &request.headers {
                outgoing = outgoing.header(key, value);
            }
            let mut response = outgoing.send().await.map_err(map_reqwest_error)?;
            let status = response.status();
            if status.is_redirection() {
                if redirect_count == request.max_redirects {
                    return Err(Error::Upstream("redirect limit exceeded".to_string()));
                }
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| Error::Upstream("redirect has no Location".to_string()))?;
                current = current
                    .join(location)
                    .map_err(|err| Error::Upstream(format!("invalid redirect: {err}")))?;
                continue;
            }
            if response
                .content_length()
                .is_some_and(|length| length > request.max_bytes as u64)
            {
                return Err(Error::PayloadTooLarge {
                    limit: request.max_bytes,
                });
            }
            let headers = response
                .headers()
                .iter()
                .filter_map(|(key, value)| {
                    Some((key.to_string(), value.to_str().ok()?.to_string()))
                })
                .collect();
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(map_reqwest_error)? {
                if body.len().saturating_add(chunk.len()) > request.max_bytes {
                    return Err(Error::PayloadTooLarge {
                        limit: request.max_bytes,
                    });
                }
                body.extend_from_slice(&chunk);
            }
            return Ok(FetchedContent {
                body: String::from_utf8(body)
                    .map_err(|err| Error::Upstream(format!("body is not UTF-8: {err}")))?,
                headers,
                status: status.as_u16(),
                final_url: current.to_string(),
            });
        }
        Err(Error::Upstream("redirect processing failed".to_string()))
    }

    async fn read_file(&self, path: &str) -> subconverter_core::Result<String> {
        fs::read_to_string(path).map_err(|err| Error::Io(format!("{path}: {err}")))
    }

    async fn write_file(
        &self,
        path: &str,
        content: &str,
        overwrite: bool,
    ) -> subconverter_core::Result<()> {
        if !overwrite && Path::new(path).exists() {
            return Err(Error::Io(format!("file already exists: {path}")));
        }
        fs::write(path, content).map_err(|err| Error::Io(format!("{path}: {err}")))
    }

    async fn flush_cache(&self) -> subconverter_core::Result<()> {
        Ok(())
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            persistent_config: false,
            cache_management: false,
            local_files: true,
            trusted_local_files: true,
            raw_fetch_routes: false,
            local_management_routes: false,
            scripts: true,
            cron: false,
            gist_upload: false,
        }
    }
}

fn map_reqwest_error(err: reqwest::Error) -> Error {
    if err.is_timeout() {
        Error::Timeout(err.to_string())
    } else {
        Error::Upstream(err.to_string())
    }
}

fn validate_cli_url(url: &reqwest::Url, request: &FetchRequest) -> subconverter_core::Result<()> {
    match url.scheme() {
        "https" => {}
        "http" if request.allow_plain_http => {}
        "http" => {
            return Err(Error::Forbidden(
                "plain HTTP upstreams are disabled".to_string(),
            ));
        }
        scheme => {
            return Err(Error::Forbidden(format!(
                "unsupported upstream URL scheme: {scheme}"
            )));
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::Forbidden(
            "credentials in upstream URLs are not allowed".to_string(),
        ));
    }
    Ok(())
}

fn is_non_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_documentation()
                || octets[0] == 0
                || octets[0] >= 240
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        }
        IpAddr::V6(ip) => is_non_public_ipv6(ip),
    }
}

fn is_non_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_non_public_ip(mapped.into());
    }
    let segments = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || segments[0] == 0x2001 && segments[1] == 0x0db8
}

fn emit_artifact(
    artifact: Option<&str>,
    target: &str,
    output: &str,
    multi_target: bool,
) -> Result<()> {
    let Some(artifact) = artifact else {
        if !multi_target {
            println!("{output}");
        }
        return Ok(());
    };
    let artifact_path = Path::new(artifact);
    let output_path = if multi_target {
        fs::create_dir_all(artifact_path).with_context(|| {
            format!(
                "failed to create artifact directory {}",
                artifact_path.display()
            )
        })?;
        artifact_path.join(format!("{target}.txt"))
    } else {
        if let Some(parent) = artifact_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create artifact directory {}", parent.display())
            })?;
        }
        artifact_path.to_path_buf()
    };
    fs::write(&output_path, output)
        .with_context(|| format!("failed to write artifact {}", output_path.display()))?;
    Ok(())
}

fn write_log(path: &Path, message: &str) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create log directory {}", parent.display()))?;
    }
    fs::write(path, message).with_context(|| format!("failed to write log {}", path.display()))
}

fn generator_targets() -> &'static [&'static str] {
    &[
        "clash",
        "clashr",
        "quan",
        "quanx",
        "loon",
        "ss",
        "sssub",
        "ssd",
        "ssr",
        "surfboard",
        "surge",
        "mellow",
        "v2ray",
        "trojan",
        "singbox",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_with_defaults() -> Args {
        Args {
            pref: None,
            generator_mode: false,
            artifact: None,
            log: None,
            target: None,
            url: None,
            config: None,
            include: None,
            exclude: None,
            group: None,
            rename: Vec::new(),
            append_type: None,
            sort: None,
            udp: None,
            tfo: None,
            scv: None,
            tls13: None,
            nodelist: None,
            fdn: None,
            expand: None,
            classic: None,
            surge_version: None,
        }
    }

    #[test]
    fn cli_convert_options_map_compatibility_flags() {
        let mut args = args_with_defaults();
        args.include = Some("HK|TW".to_string());
        args.exclude = Some("Drop,Test".to_string());
        args.group = Some("Custom".to_string());
        args.rename = vec!["Alpha@Beta".to_string()];
        args.append_type = Some("true".to_string());
        args.sort = Some("true".to_string());
        args.udp = Some("false".to_string());
        args.tfo = Some("true".to_string());
        args.scv = Some("true".to_string());
        args.tls13 = Some("true".to_string());
        args.nodelist = Some("true".to_string());
        args.fdn = Some("false".to_string());
        args.expand = Some("false".to_string());
        args.classic = Some("true".to_string());

        let options = convert_options_from_args(&args);

        assert_eq!(options.include_remarks, vec!["HK", "TW"]);
        assert_eq!(options.exclude_remarks, vec!["Drop", "Test"]);
        assert_eq!(options.node_group.as_deref(), Some("Custom"));
        assert_eq!(options.rename_node[0].r#match, "Alpha");
        assert_eq!(options.rename_node[0].replace, "Beta");
        assert!(options.append_proxy_type.get(false));
        assert!(options.sort.get(false));
        assert!(!options.udp.get(true));
        assert!(options.tcp_fast_open.get(false));
        assert!(options.skip_cert_verify.get(false));
        assert!(options.tls13.get(false));
        assert!(options.nodelist.get(false));
        assert!(!options.filter_deprecated.get(true));
        assert!(!options.expand_rulesets.get(true));
        assert!(options.classic_ruleset.get(false));
    }
}
