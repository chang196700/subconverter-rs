use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Component, Path};

use crate::config::{expand_imports_with, import_refs};
use crate::convert::{
    apply_settings_defaults_to_options, convert_subscription_with_settings,
    derive_subscription_userinfo_with_context, execute_subscription_script, ConvertOptions,
    ConvertRequest, RuntimeContext, SurgeVersion, Target,
};
use crate::io::{FetchRequest, FetchedContent, PlatformIo};
use crate::model::{RegexMatchConfig, TriBool};
use crate::rules::{convert_ruleset, RulesetOutput};
use crate::template;
use crate::util::{base64_decode, parse_query, url_decode, url_encode, url_safe_base64_decode};
use crate::{Error, Result, SecuritySettings, Settings, VERSION};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreRequest {
    pub method: Method,
    pub path: String,
    pub query: String,
    pub body: String,
    pub headers: BTreeMap<String, String>,
}

impl CoreRequest {
    pub fn query_args(&self) -> BTreeMap<String, String> {
        parse_query(&self.query)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreResponse {
    pub status: u16,
    pub content_type: String,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

impl CoreResponse {
    pub fn text(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type: "text/plain;charset=utf-8".to_string(),
            headers: BTreeMap::new(),
            body: body.into(),
        }
    }

    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }
}

pub async fn handle_request<I: PlatformIo>(
    io: &I,
    settings: &mut Settings,
    request: CoreRequest,
) -> CoreResponse {
    handle_request_with_context(io, settings, request, RuntimeContext::system()).await
}

pub async fn handle_request_with_context<I: PlatformIo>(
    io: &I,
    settings: &mut Settings,
    request: CoreRequest,
    context: RuntimeContext,
) -> CoreResponse {
    let mut response = match dispatch(io, settings, &request, context).await {
        Ok(mut response) => {
            if request.method == Method::Head {
                response.body.clear();
            }
            response
        }
        Err(err) => CoreResponse::text(err.status_code(), format!("{err}\n")),
    };
    if request.method == Method::Head {
        response.body.clear();
        response.content_type = "text/plain".to_string();
    }
    response
}

async fn dispatch<I: PlatformIo>(
    io: &I,
    settings: &mut Settings,
    request: &CoreRequest,
    context: RuntimeContext,
) -> Result<CoreResponse> {
    match (request.method, request.path.as_str()) {
        (Method::Get, "/version") => Ok(CoreResponse::text(
            200,
            format!("subconverter v{VERSION} backend\n"),
        )),
        (Method::Get, "/refreshrules") => {
            require_capability(io.capabilities().cache_management, "ruleset refresh")?;
            require_token(settings, &request.query_args())?;
            io.flush_cache().await?;
            Ok(CoreResponse::text(200, "done\n"))
        }
        (Method::Get, "/readconf") => {
            require_capability(io.capabilities().persistent_config, "readconf")?;
            require_token(settings, &request.query_args())?;
            let content = read_pref_content(io).await?;
            let expanded = expand_config_imports(io, settings, &content, true).await?;
            *settings = Settings::detect_and_parse(&expanded)?;
            Ok(CoreResponse::text(200, "done\n"))
        }
        (Method::Post, "/updateconf") => {
            require_capability(io.capabilities().persistent_config, "updateconf")?;
            require_token(settings, &request.query_args())?;
            let args = request.query_args();
            match args.get("type").map(String::as_str) {
                Some("form" | "direct") => {
                    let pref_path = find_pref_path(io).await;
                    let expanded = expand_config_imports(io, settings, &request.body, true).await?;
                    io.write_file(&pref_path, &request.body, true).await?;
                    *settings = Settings::detect_and_parse(&expanded)?;
                    Ok(CoreResponse::text(200, "done\n"))
                }
                _ => Err(Error::UnsupportedAdapterFeature(
                    "updateconf type".to_string(),
                )),
            }
        }
        (Method::Get, "/flushcache") => {
            require_capability(io.capabilities().cache_management, "flushcache")?;
            require_token(settings, &request.query_args())?;
            io.flush_cache().await?;
            Ok(CoreResponse::text(200, "done"))
        }
        (Method::Get | Method::Head, "/sub") => sub(io, settings, request, context).await,
        (Method::Get, "/sub2clashr") => {
            sub_with_target(io, settings, request, "clashr", context).await
        }
        (Method::Get, "/surge2clash") => {
            sub_with_target(io, settings, request, "clash", context).await
        }
        (Method::Get, "/getruleset") => get_ruleset(io, settings, request).await,
        (Method::Get, "/getprofile") => get_profile(io, settings, request, context).await,
        (Method::Get, "/render") => render_template(io, settings, request).await,
        (Method::Get, "/get") => {
            require_capability(io.capabilities().raw_fetch_routes, "get")?;
            if settings.api_mode {
                return Ok(CoreResponse::text(404, "Not Found\n"));
            }
            let args = request.query_args();
            let url = args
                .get("url")
                .map(|value| url_decode(value))
                .ok_or(Error::MissingArgument("url"))?;
            let fetched = fetch_remote(io, settings, &url, "subscription").await?;
            Ok(CoreResponse::text(200, fetched.body))
        }
        (Method::Get, "/getlocal") => {
            require_capability(io.capabilities().local_management_routes, "getlocal")?;
            if settings.api_mode {
                return Ok(CoreResponse::text(404, "Not Found\n"));
            }
            let args = request.query_args();
            require_local_access(io, settings, &args)?;
            let path = args
                .get("path")
                .map(|value| url_decode(value))
                .ok_or(Error::MissingArgument("path"))?;
            validate_adapter_local_path(io, &path, &settings.security)?;
            Ok(CoreResponse::text(200, io.read_file(&path).await?))
        }
        _ => Ok(CoreResponse::text(404, "Not Found\n")),
    }
}

async fn sub<I: PlatformIo>(
    io: &I,
    settings: &Settings,
    request: &CoreRequest,
    context: RuntimeContext,
) -> Result<CoreResponse> {
    let args = request.query_args();
    let target = args.get("target").ok_or(Error::MissingArgument("target"))?;
    let target = resolve_target_alias(target, request)?;
    sub_with_target(io, settings, request, &target, context).await
}

async fn sub_with_target<I: PlatformIo>(
    io: &I,
    settings: &Settings,
    request: &CoreRequest,
    target: &str,
    context: RuntimeContext,
) -> Result<CoreResponse> {
    let args = request.query_args();
    let target = Target::parse(&resolve_target_alias(target, request)?)?;
    let local_authorized =
        has_valid_token(settings, &args) || io.capabilities().trusted_local_files;
    let config = match args.get("config") {
        Some(value) => {
            Some(resolve_config_content(io, settings, &url_decode(value), local_authorized).await?)
        }
        None if !settings.default_external_config.is_empty() => Some(
            resolve_config_content(io, settings, &settings.default_external_config, true).await?,
        ),
        None => None,
    };
    let config = merge_request_config(config, &args);
    let config_is_trusted = !args.contains_key("config")
        || has_valid_token(settings, &args)
        || io.capabilities().trusted_local_files;
    let settings_for_config = config.as_deref().and_then(|content| {
        Settings::overlay(content, settings).ok().map(|mut merged| {
            if !config_is_trusted {
                merged.api_mode = settings.api_mode;
                merged.api_access_token = settings.api_access_token.clone();
                merged.security = settings.security.clone();
            }
            merged
        })
    });
    let mut effective_settings = settings_for_config.unwrap_or_else(|| settings.clone());
    let scripts_authorized =
        has_valid_token(settings, &args) || io.capabilities().trusted_local_files;
    if let Some(filter_script) = args.get("filter_script") {
        effective_settings.enable_filter = true;
        effective_settings.filter_script = filter_script.clone();
    }
    resolve_configured_scripts(io, &mut effective_settings, scripts_authorized).await?;
    let insert_enabled = parse_tribool_arg(&args, "insert").get(effective_settings.enable_insert);
    let prepend_insert =
        parse_tribool_arg(&args, "prepend").get(effective_settings.prepend_insert_url);
    let local_authorized =
        has_valid_token(&effective_settings, &args) || io.capabilities().trusted_local_files;
    let api_authorized =
        !effective_settings.api_mode || has_valid_token(&effective_settings, &args);
    let default_url = if api_authorized && !effective_settings.default_urls.is_empty() {
        Some(effective_settings.default_urls.join("|"))
    } else {
        None
    };
    let mut resolved_sources = match args
        .get("url")
        .map(String::as_str)
        .or(default_url.as_deref())
    {
        Some(raw_url) => {
            resolve_sources(
                io,
                &url_decode(raw_url),
                &effective_settings,
                local_authorized,
                scripts_authorized,
                context,
            )
            .await?
        }
        None if insert_enabled && !effective_settings.insert_urls.is_empty() => Vec::new(),
        None => return Err(Error::MissingArgument("url")),
    };
    if insert_enabled && !effective_settings.insert_urls.is_empty() {
        let mut insert_sources = resolve_sources(
            io,
            &effective_settings.insert_urls.join("|"),
            &effective_settings,
            true,
            scripts_authorized,
            context,
        )
        .await?;
        if prepend_insert {
            insert_sources.extend(resolved_sources);
            resolved_sources = insert_sources;
        } else {
            resolved_sources.extend(insert_sources);
        }
    }
    if resolved_sources.is_empty() {
        return Err(Error::InvalidRequest("No nodes were found!".to_string()));
    }
    let remote_subscription_userinfo = first_subscription_userinfo(&resolved_sources);
    let sources = resolved_sources
        .into_iter()
        .map(|source| source.body)
        .collect::<Vec<_>>();
    let subscription_userinfo = remote_subscription_userinfo.or_else(|| {
        derive_subscription_userinfo_with_context(&sources, Some(&effective_settings), context)
    });
    let surge_version = args
        .get("ver")
        .map(|value| value.parse::<SurgeVersion>())
        .transpose()?;
    if parse_tribool_arg(&args, "upload").get(false) {
        require_capability(io.capabilities().gist_upload, "Gist upload")?;
        if !scripts_authorized {
            return Err(Error::Forbidden(
                "Gist upload requires an authorized request".to_string(),
            ));
        }
    }
    let mut options = convert_options_from_args(&args);
    apply_settings_defaults_to_options(&effective_settings, &mut options);
    let context = context.with_scripts_authorized(scripts_authorized);
    let mut output = convert_subscription_with_settings(
        ConvertRequest {
            target,
            sources,
            config: None,
            user_agent: None,
            surge_version,
            options: options.clone(),
        },
        Some(effective_settings.clone()),
        context,
    )?;
    upload_if_requested(io, target, surge_version, &args, &options, &output).await?;
    output = apply_managed_config_prefix(output, target, settings, request, &args, &options);
    Ok(apply_sub_response_headers(
        CoreResponse::text(200, output),
        &effective_settings,
        &args,
        subscription_userinfo.as_deref(),
    ))
}

async fn upload_if_requested<I: PlatformIo>(
    io: &I,
    target: Target,
    surge_version: Option<SurgeVersion>,
    args: &BTreeMap<String, String>,
    options: &ConvertOptions,
    output: &str,
) -> Result<()> {
    if !parse_tribool_arg(args, "upload").get(false) {
        return Ok(());
    }
    let upload_path = args.get("upload_path").map(String::as_str).unwrap_or("");
    let (name, write_managed_url) = upload_target_name(target, surge_version, options);
    io.upload_gist(name, upload_path, output, write_managed_url)
        .await
}

fn upload_target_name(
    target: Target,
    surge_version: Option<SurgeVersion>,
    options: &ConvertOptions,
) -> (&'static str, bool) {
    match target {
        Target::Surge if options.nodelist.get(false) => match surge_version {
            Some(SurgeVersion::V2) => ("surge2list", true),
            Some(SurgeVersion::V3) => ("surge3list", true),
            Some(SurgeVersion::V4) => ("surge4list", true),
            _ => ("surgelist", true),
        },
        Target::Surge => match surge_version {
            Some(SurgeVersion::V2) => ("surge2", true),
            Some(SurgeVersion::V3) => ("surge3", true),
            Some(SurgeVersion::V4) => ("surge4", true),
            _ => ("surge", true),
        },
        Target::Surfboard => ("surfboard", true),
        Target::Clash => ("clash", false),
        Target::ClashR => ("clashr", false),
        Target::ShadowsocksSub => ("sssub", false),
        Target::Shadowsocks => ("ss", false),
        Target::ShadowsocksR => ("ssr", false),
        Target::V2Ray => ("v2ray", false),
        Target::Trojan => ("trojan", false),
        Target::Mixed => ("sub", false),
        Target::Mellow => ("mellow", true),
        Target::Quan => ("quan", false),
        Target::QuanX => ("quanx", false),
        Target::Loon => ("loon", false),
        Target::Ssd => ("ssd", false),
        Target::SingBox => ("singbox", false),
    }
}

fn apply_managed_config_prefix(
    output: String,
    target: Target,
    settings: &Settings,
    request: &CoreRequest,
    args: &BTreeMap<String, String>,
    options: &ConvertOptions,
) -> String {
    if !matches!(target, Target::Surge | Target::Surfboard)
        || options.nodelist.get(false)
        || !settings.write_managed_config
        || settings.managed_config_prefix.is_empty()
    {
        return output;
    }
    let managed_url = args
        .get("profile_data")
        .and_then(|value| base64_decode(value).ok())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("{}/sub?{}", settings.managed_config_prefix, request.query));
    let interval = args
        .get("interval")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(settings.config_update_interval);
    let strict = args
        .get("strict")
        .map(|value| value == "true")
        .unwrap_or(settings.config_update_strict);
    let interval_part = if interval > 0 {
        format!(" interval={interval}")
    } else {
        String::new()
    };
    format!("#!MANAGED-CONFIG {managed_url}{interval_part} strict={strict}\n\n{output}")
}

fn apply_sub_response_headers(
    mut response: CoreResponse,
    settings: &Settings,
    args: &BTreeMap<String, String>,
    subscription_userinfo: Option<&str>,
) -> CoreResponse {
    let interval = args
        .get("interval")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    if interval > 0 {
        response = response.with_header("profile-update-interval", (interval / 3600).to_string());
    }
    if let Some(filename) = args.get("filename").filter(|value| !value.is_empty()) {
        response = response.with_header(
            "content-disposition",
            format!(
                "attachment; filename=\"{}\"; filename*=utf-8''{}",
                filename,
                url_encode(filename)
            ),
        );
    }
    let append_userinfo = parse_tribool_arg(args, "append_info").get(settings.append_sub_userinfo);
    if append_userinfo {
        if let Some(userinfo) = subscription_userinfo.filter(|value| !value.is_empty()) {
            response = response.with_header("Subscription-UserInfo", userinfo);
        }
    }
    response
}

fn resolve_target_alias(target: &str, request: &CoreRequest) -> Result<String> {
    if !target.eq_ignore_ascii_case("auto") {
        return Ok(target.to_string());
    }
    let user_agent = header_value(&request.headers, "user-agent").unwrap_or_default();
    infer_target_from_user_agent(user_agent)
        .ok_or_else(|| Error::UnsupportedTarget(target.to_string()))
        .map(str::to_string)
}

fn header_value<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn infer_target_from_user_agent(user_agent: &str) -> Option<&'static str> {
    let ua = user_agent.to_ascii_lowercase();
    if ua.is_empty() {
        return None;
    }
    if ua.contains("clash") {
        return Some("clash");
    }
    if ua.contains("surge") {
        return Some("surge");
    }
    if ua.contains("quantumult%20x") || ua.contains("quantumult x") {
        return Some("quanx");
    }
    if ua.contains("quantumult") {
        return Some("quan");
    }
    if ua.contains("loon") {
        return Some("loon");
    }
    if ua.contains("surfboard") {
        return Some("surfboard");
    }
    if ua.contains("kitsunebi") || ua.contains("qv2ray") || ua.contains("v2ray") {
        return Some("v2ray");
    }
    if ua.contains("shadowrocket") || ua.contains("pharos") || ua.contains("potatso") {
        return Some("mixed");
    }
    if ua.contains("trojan-qt5") {
        return Some("mixed");
    }
    None
}

fn merge_request_config(config: Option<String>, args: &BTreeMap<String, String>) -> Option<String> {
    let mut overlay = String::new();
    if let Some(groups) = args
        .get("groups")
        .and_then(|value| decode_request_block(value))
    {
        overlay.push_str("[rulesets]\n");
        for group in split_request_block(&groups) {
            overlay.push_str("custom_proxy_group=");
            overlay.push_str(group);
            overlay.push('\n');
        }
    }
    if let Some(rulesets) = args
        .get("ruleset")
        .or_else(|| args.get("rulesets"))
        .and_then(|value| decode_request_block(value))
    {
        if !overlay.contains("[rulesets]\n") {
            overlay.push_str("[rulesets]\n");
        }
        for ruleset in split_request_block(&rulesets) {
            overlay.push_str("ruleset=");
            overlay.push_str(ruleset);
            overlay.push('\n');
        }
    }
    if overlay.is_empty() {
        return config;
    }
    Some(match config {
        Some(config) if !config.trim().is_empty() => format!("{config}\n{overlay}"),
        _ => overlay,
    })
}

fn decode_request_block(value: &str) -> Option<String> {
    url_safe_base64_decode(value)
        .ok()
        .or_else(|| crate::util::base64_decode(value).ok())
        .or_else(|| Some(value.to_string()))
}

fn split_request_block(value: &str) -> Vec<&str> {
    value
        .split(['@', '\n', '\r'])
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .collect()
}

fn convert_options_from_args(args: &BTreeMap<String, String>) -> ConvertOptions {
    let mut options = ConvertOptions {
        include_remarks: split_request_patterns(args.get("include")),
        exclude_remarks: split_request_patterns(args.get("exclude")),
        node_group: args.get("group").filter(|value| !value.is_empty()).cloned(),
        rename_node: parse_rename_arg(args.get("rename")),
        add_emoji: parse_tribool_arg(args, "add_emoji")
            .or(parse_tribool_arg(args, "emoji"))
            .or(parse_tribool_arg(args, "addemoji")),
        remove_emoji: parse_tribool_arg(args, "remove_emoji")
            .or(parse_tribool_arg(args, "removeemoji")),
        append_proxy_type: parse_tribool_arg(args, "append_type"),
        sort: parse_tribool_arg(args, "sort"),
        udp: parse_tribool_arg(args, "udp"),
        tcp_fast_open: parse_tribool_arg(args, "tfo"),
        skip_cert_verify: parse_tribool_arg(args, "scv")
            .or(parse_tribool_arg(args, "skip_cert_verify")),
        tls13: parse_tribool_arg(args, "tls13"),
        nodelist: parse_tribool_arg(args, "list"),
        filter_deprecated: parse_tribool_arg(args, "fdn"),
        expand_rulesets: parse_tribool_arg(args, "expand"),
        classic_ruleset: parse_tribool_arg(args, "classic"),
        ..ConvertOptions::default()
    };
    if let Some(emoji) = args.get("emoji_rules").or_else(|| args.get("emoji_rule")) {
        options.emoji = parse_emoji_rules(emoji);
    }
    options
}

fn parse_tribool_arg(args: &BTreeMap<String, String>, key: &str) -> TriBool {
    args.get(key)
        .map(|value| TriBool::parse(value))
        .unwrap_or_default()
}

fn split_request_patterns(value: Option<&String>) -> Vec<String> {
    value
        .map(|value| {
            value
                .split(['`', '|'])
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn parse_rename_arg(value: Option<&String>) -> Vec<RegexMatchConfig> {
    value
        .into_iter()
        .flat_map(|value| value.split('`'))
        .filter_map(|item| {
            let (r#match, replace) = item.split_once('@')?;
            Some(RegexMatchConfig {
                script: None,
                r#match: r#match.trim().to_string(),
                replace: replace.trim().to_string(),
            })
        })
        .collect()
}

fn parse_emoji_rules(value: &str) -> Vec<RegexMatchConfig> {
    value
        .split('`')
        .filter_map(|item| {
            let (r#match, replace) = item.split_once(',')?;
            Some(RegexMatchConfig {
                script: None,
                r#match: r#match.trim().to_string(),
                replace: replace.trim().to_string(),
            })
        })
        .collect()
}

async fn resolve_configured_scripts<I: PlatformIo>(
    io: &I,
    settings: &mut Settings,
    authorized: bool,
) -> Result<()> {
    let requested = (settings.enable_filter && !settings.filter_script.is_empty())
        || !settings.sort_script.is_empty()
        || settings
            .rename_node
            .iter()
            .chain(settings.emoji.iter())
            .chain(settings.stream_rule.iter())
            .chain(settings.time_rule.iter())
            .any(|rule| rule.script.is_some());
    if !requested {
        return Ok(());
    }
    require_capability(io.capabilities().scripts, "QuickJS scripts")?;
    if !authorized {
        return Err(Error::Forbidden(
            "scripts require an authorized request".to_string(),
        ));
    }
    settings.filter_script =
        resolve_script_source(io, &settings.security, &settings.filter_script).await?;
    settings.sort_script =
        resolve_script_source(io, &settings.security, &settings.sort_script).await?;
    for rule in settings
        .rename_node
        .iter_mut()
        .chain(settings.emoji.iter_mut())
        .chain(settings.stream_rule.iter_mut())
        .chain(settings.time_rule.iter_mut())
    {
        if let Some(script) = rule.script.take() {
            rule.script = Some(resolve_script_source(io, &settings.security, &script).await?);
        }
    }
    Ok(())
}

async fn resolve_script_source<I: PlatformIo>(
    io: &I,
    security: &SecuritySettings,
    source: &str,
) -> Result<String> {
    if source.is_empty() {
        return Ok(String::new());
    }
    if let Some(path) = source.strip_prefix("path:") {
        validate_adapter_local_path(io, path, security)?;
        return io.read_file(path).await;
    }
    Ok(source.replace("\\r\\n", "\n").replace("\\n", "\n"))
}

async fn resolve_sources<I: PlatformIo>(
    io: &I,
    raw: &str,
    settings: &Settings,
    local_authorized: bool,
    scripts_authorized: bool,
    context: RuntimeContext,
) -> Result<Vec<FetchedContent>> {
    let mut sources = Vec::new();
    for source in raw
        .split('|')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let resolved = if source.starts_with("script:") {
            resolve_script_subscription(io, settings, source, scripts_authorized, context).await
        } else if source.starts_with("http://") || source.starts_with("https://") {
            fetch_remote(io, settings, source, "subscription").await
        } else if source.starts_with("file://") {
            if !local_authorized {
                return Err(Error::Forbidden(
                    "a valid token is required for local subscription files".to_string(),
                ));
            }
            let path = source.trim_start_matches("file://");
            validate_adapter_local_path(io, path, &settings.security)?;
            Ok(FetchedContent {
                body: io.read_file(source.trim_start_matches("file://")).await?,
                headers: BTreeMap::new(),
                status: 200,
                final_url: source.to_string(),
            })
        } else if looks_like_inline_subscription(source) {
            Ok(FetchedContent {
                body: source.to_string(),
                headers: BTreeMap::new(),
                status: 200,
                final_url: source.to_string(),
            })
        } else if looks_like_local_path(source) {
            if !local_authorized {
                return Err(Error::Forbidden(
                    "a valid token is required for local subscription files".to_string(),
                ));
            }
            validate_adapter_local_path(io, source, &settings.security)?;
            Ok(FetchedContent {
                body: io.read_file(source).await?,
                headers: BTreeMap::new(),
                status: 200,
                final_url: source.to_string(),
            })
        } else {
            Ok(FetchedContent {
                body: source.to_string(),
                headers: BTreeMap::new(),
                status: 200,
                final_url: source.to_string(),
            })
        };
        match resolved {
            Ok(source) => sources.push(source),
            Err(_) if settings.skip_failed_links => {}
            Err(err) => return Err(err),
        }
    }
    Ok(sources)
}

async fn resolve_script_subscription<I: PlatformIo>(
    io: &I,
    settings: &Settings,
    source: &str,
    authorized: bool,
    context: RuntimeContext,
) -> Result<FetchedContent> {
    require_capability(io.capabilities().scripts, "subscription scripts")?;
    if !authorized {
        return Err(Error::Forbidden(
            "subscription scripts require an authorized request".to_string(),
        ));
    }
    let mut parts = source
        .trim_start_matches("script:")
        .split(',')
        .map(str::trim);
    let path = parts
        .next()
        .filter(|path| !path.is_empty())
        .ok_or_else(|| Error::InvalidRequest("subscription script path is empty".to_string()))?;
    validate_adapter_local_path(io, path, &settings.security)?;
    let script = io.read_file(path).await?;
    let arguments = parts.map(ToOwned::to_owned).collect::<Vec<_>>();
    let first = arguments.first().map(String::as_str).unwrap_or("");
    let remaining = arguments.get(1..).unwrap_or(&[]);
    let body = execute_subscription_script(
        &script,
        first,
        remaining,
        settings,
        context.with_scripts_authorized(true),
    )?;
    Ok(FetchedContent {
        body,
        headers: BTreeMap::new(),
        status: 200,
        final_url: source.to_string(),
    })
}

fn first_subscription_userinfo(sources: &[FetchedContent]) -> Option<String> {
    sources.iter().find_map(|source| {
        source
            .headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("Subscription-UserInfo"))
            .map(|(_, value)| value.clone())
    })
}

fn looks_like_proxy_link(source: &str) -> bool {
    source.starts_with("ss://")
        || source.starts_with("ssr://")
        || source.starts_with("vmess://")
        || source.starts_with("trojan://")
        || source.starts_with("snell://")
        || source.starts_with("wireguard://")
        || source.starts_with("hysteria://")
        || source.starts_with("hysteria2://")
        || source.starts_with("hy2://")
        || source.starts_with("tg://")
        || source.starts_with("https://t.me/")
}

fn looks_like_inline_subscription(source: &str) -> bool {
    looks_like_proxy_link(source)
        || source.contains('\n')
        || source.starts_with('{')
        || source.starts_with('[')
        || source
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '_' | '-' | '='))
}

fn looks_like_local_path(source: &str) -> bool {
    source.contains('/')
        || source.contains('\\')
        || source.starts_with('.')
        || [
            ".txt", ".conf", ".ini", ".toml", ".yaml", ".yml", ".json", ".list",
        ]
        .iter()
        .any(|suffix| source.to_ascii_lowercase().ends_with(suffix))
}

async fn resolve_optional_content<I: PlatformIo>(
    io: &I,
    settings: &Settings,
    raw: &str,
    local_authorized: bool,
    cache_namespace: &str,
) -> Result<String> {
    if raw.starts_with("http://") || raw.starts_with("https://") {
        Ok(fetch_remote(io, settings, raw, cache_namespace).await?.body)
    } else if raw.starts_with("file://") {
        if !local_authorized {
            return Err(Error::Forbidden(
                "a valid token is required for local files".to_string(),
            ));
        }
        let path = raw.trim_start_matches("file://");
        validate_adapter_local_path(io, path, &settings.security)?;
        io.read_file(path).await
    } else if raw.contains('\n') || raw.contains("[common]") || raw.contains("node_pref") {
        Ok(raw.to_string())
    } else if looks_like_local_path(raw) {
        if !local_authorized {
            return Err(Error::Forbidden(
                "a valid token is required for local files".to_string(),
            ));
        }
        validate_adapter_local_path(io, raw, &settings.security)?;
        io.read_file(raw).await
    } else {
        Ok(raw.to_string())
    }
}

async fn resolve_config_content<I: PlatformIo>(
    io: &I,
    settings: &Settings,
    raw: &str,
    local_authorized: bool,
) -> Result<String> {
    let content = resolve_optional_content(io, settings, raw, local_authorized, "config").await?;
    let content = expand_config_imports(io, settings, &content, local_authorized).await?;
    let Ok(parsed_settings) = Settings::detect_and_parse(&content) else {
        return Ok(content);
    };
    let format = ConfigSyntax::detect(&content);
    let mut resolved = content;
    for (field, value) in rule_base_refs(&parsed_settings) {
        if value.is_empty() || looks_like_inline_yaml(value) {
            continue;
        }
        if let Ok(base_content) =
            resolve_optional_content(io, settings, value, local_authorized, "config").await
        {
            resolved = replace_rule_base_field(&resolved, format, field, &base_content);
        }
    }
    Ok(resolved)
}

async fn read_pref_content<I: PlatformIo>(io: &I) -> Result<String> {
    for file in ["pref.toml", "pref.yml", "pref.yaml", "pref.ini"] {
        if let Ok(content) = io.read_file(file).await {
            return Ok(content);
        }
    }
    Err(Error::Io("no pref file found".to_string()))
}

async fn find_pref_path<I: PlatformIo>(io: &I) -> String {
    for file in ["pref.toml", "pref.yml", "pref.yaml", "pref.ini"] {
        if io.read_file(file).await.is_ok() {
            return file.to_string();
        }
    }
    "pref.toml".to_string()
}

async fn expand_config_imports<I: PlatformIo>(
    io: &I,
    settings: &Settings,
    content: &str,
    local_authorized: bool,
) -> Result<String> {
    let mut current = content.to_string();
    for _ in 0..8 {
        let refs = import_refs(&current);
        if refs.is_empty() {
            return Ok(current);
        }
        let mut loaded = BTreeMap::new();
        for reference in refs {
            let content =
                resolve_optional_content(io, settings, &reference, local_authorized, "config")
                    .await?;
            loaded.insert(reference, content);
        }
        current = expand_imports_with(&current, |reference| {
            loaded
                .get(reference)
                .cloned()
                .ok_or_else(|| Error::Io(format!("missing import: {reference}")))
        })?;
    }
    Err(Error::Parse(
        "config import recursion limit exceeded".to_string(),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfigSyntax {
    Ini,
    Toml,
    Yaml,
}

impl ConfigSyntax {
    fn detect(content: &str) -> Self {
        if content.contains("[common]")
            || content.contains("[node_pref]")
            || content.contains("[managed_config]")
            || content.contains("[rulesets]")
            || content.contains("[emojis]")
            || content.contains("[userinfo]")
            || content.contains("[custom]")
        {
            Self::Ini
        } else if content.contains("common:")
            || content.contains("node_pref:")
            || content.contains("rulesets:")
            || content.contains("proxy_groups:")
            || content.contains("emojis:")
            || content.contains("managed_config:")
            || content.contains("template:")
        {
            Self::Yaml
        } else {
            Self::Toml
        }
    }
}

fn rule_base_refs(settings: &Settings) -> [(&'static str, &str); 9] {
    [
        ("clash_rule_base", &settings.clash_rule_base),
        ("surge_rule_base", &settings.surge_rule_base),
        ("surfboard_rule_base", &settings.surfboard_rule_base),
        ("mellow_rule_base", &settings.mellow_rule_base),
        ("quan_rule_base", &settings.quan_rule_base),
        ("quanx_rule_base", &settings.quanx_rule_base),
        ("loon_rule_base", &settings.loon_rule_base),
        ("sssub_rule_base", &settings.sssub_rule_base),
        ("singbox_rule_base", &settings.singbox_rule_base),
    ]
}

fn replace_rule_base_field(
    config: &str,
    format: ConfigSyntax,
    field: &str,
    base_content: &str,
) -> String {
    let mut replaced = false;
    let mut lines = Vec::new();
    for line in config.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with(field) {
            let indent = &line[..line.len() - trimmed.len()];
            let replacement = rule_base_replacement(format, field, base_content, indent);
            lines.push(replacement.clone());
            replaced = true;
        } else {
            lines.push(line.to_string());
        }
    }
    if !replaced {
        let replacement = rule_base_replacement(format, field, base_content, "");
        lines.push(replacement);
    }
    lines.join("\n")
}

fn rule_base_replacement(
    format: ConfigSyntax,
    field: &str,
    base_content: &str,
    indent: &str,
) -> String {
    match format {
        ConfigSyntax::Ini => format!(
            "{indent}{field}={}",
            base_content
                .trim_end_matches('\n')
                .replace('\r', "")
                .replace('\n', "\\n")
        ),
        ConfigSyntax::Toml => {
            format!(
                "{indent}{field} = '''\n{}\n{indent}'''",
                base_content.trim_end_matches('\n')
            )
        }
        ConfigSyntax::Yaml => {
            let content_indent = format!("{indent}  ");
            format!(
                "{indent}{field}: |-\n{}",
                base_content
                    .trim_end_matches('\n')
                    .lines()
                    .map(|line| format!("{content_indent}{line}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        }
    }
}

fn looks_like_inline_yaml(value: &str) -> bool {
    value.lines().any(|line| {
        let trimmed = line.trim_start();
        !trimmed.starts_with('#') && trimmed.contains(':')
    })
}

async fn get_ruleset<I: PlatformIo>(
    io: &I,
    settings: &Settings,
    request: &CoreRequest,
) -> Result<CoreResponse> {
    let args = request.query_args();
    let url = args.get("url").ok_or(Error::MissingArgument("url"))?;
    let rule_type = args.get("type").ok_or(Error::MissingArgument("type"))?;
    let url = url_safe_base64_decode(url)?;
    let content = if url.starts_with("http://") || url.starts_with("https://") {
        fetch_remote(io, settings, &url, "ruleset").await?.body
    } else {
        require_local_access(io, settings, &args)?;
        validate_adapter_local_path(io, &url, &settings.security)?;
        io.read_file(&url).await?
    };
    let group = args
        .get("group")
        .and_then(|value| url_safe_base64_decode(value).ok());
    let output = convert_ruleset(&content, RulesetOutput::parse(rule_type)?, group.as_deref());
    Ok(CoreResponse::text(200, output))
}

async fn get_profile<I: PlatformIo>(
    io: &I,
    settings: &Settings,
    request: &CoreRequest,
    context: RuntimeContext,
) -> Result<CoreResponse> {
    let args = request.query_args();
    let profile = args
        .get("name")
        .or_else(|| args.get("profile"))
        .ok_or(Error::MissingArgument("name"))?;
    let token = args.get("token").ok_or(Error::Unauthorized)?;
    if token.is_empty() {
        return Err(Error::Unauthorized);
    }
    let profiles = profile
        .split('|')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if profiles.is_empty() {
        return Err(Error::Unauthorized);
    }
    let content = read_profile_content(io, profiles[0]).await?;
    let mut profile_args = parse_profile_args(&content)?;
    if profiles.len() == 1 && profile_args.contains_key("profile_token") {
        let profile_token = profile_args.get("profile_token").expect("checked above");
        if token != profile_token {
            return Err(Error::Unauthorized);
        }
    } else if settings.api_access_token.is_empty() || token != &settings.api_access_token {
        return Err(Error::Unauthorized);
    }
    if profiles.len() > 1 {
        for extra_profile in profiles.iter().skip(1) {
            if let Ok(content) = read_profile_content(io, extra_profile).await {
                if let Ok(extra_args) = parse_profile_args(&content) {
                    if let Some(url) = extra_args.get("url") {
                        merge_profile_value(&mut profile_args, "url", url, "|");
                    }
                }
            }
        }
    }
    for (key, value) in args {
        if key != "name" && key != "profile" && key != "token" {
            profile_args.insert(key, value);
        }
    }
    let query = profile_args
        .iter()
        .filter(|(key, _)| key.as_str() != "profile_token")
        .map(|(key, value)| format!("{}={}", url_encode(key), url_encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    let sub_request = CoreRequest {
        method: Method::Get,
        path: "/sub".to_string(),
        query,
        body: String::new(),
        headers: request.headers.clone(),
    };
    sub(io, settings, &sub_request, context).await
}

async fn read_profile_content<I: PlatformIo>(io: &I, profile: &str) -> Result<String> {
    let candidates = if profile.contains('/') || profile.contains('\\') || profile.ends_with(".ini")
    {
        vec![profile.to_string()]
    } else {
        vec![
            format!("base/profiles/{profile}.ini"),
            format!("profiles/{profile}.ini"),
        ]
    };
    for path in candidates {
        if let Ok(content) = io.read_file(&path).await {
            return Ok(content);
        }
    }
    Err(Error::Io(format!("profile not found: {profile}")))
}

fn parse_profile_args(content: &str) -> Result<BTreeMap<String, String>> {
    let mut in_profile = false;
    let mut args = BTreeMap::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty()
            || line.starts_with(';')
            || line.starts_with('#')
            || line.starts_with("//")
        {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_profile = line[1..line.len() - 1].eq_ignore_ascii_case("Profile");
            continue;
        }
        if !in_profile {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"');
        match key {
            "url" => merge_profile_value(&mut args, key, value, "|"),
            "rename" | "exclude" | "include" => merge_profile_value(&mut args, key, value, "`"),
            _ => {
                args.insert(key.to_string(), value.to_string());
            }
        }
    }
    if args.is_empty() {
        return Err(Error::Parse(
            "profile has no [Profile] arguments".to_string(),
        ));
    }
    Ok(args)
}

fn merge_profile_value(
    args: &mut BTreeMap<String, String>,
    key: &str,
    value: &str,
    delimiter: &str,
) {
    args.entry(key.to_string())
        .and_modify(|existing| {
            if !existing.is_empty() {
                existing.push_str(delimiter);
            }
            existing.push_str(value);
        })
        .or_insert_with(|| value.to_string());
}

async fn render_template<I: PlatformIo>(
    io: &I,
    settings: &Settings,
    request: &CoreRequest,
) -> Result<CoreResponse> {
    let args = request.query_args();
    require_local_access(io, settings, &args)?;
    let path = args.get("path").ok_or(Error::MissingArgument("path"))?;
    let template_path = url_decode(path);
    validate_adapter_local_path(io, &template_path, &settings.security)?;
    let content = io.read_file(&template_path).await?;
    let config = match args.get("config") {
        Some(value) => Some(resolve_config_content(io, settings, &url_decode(value), true).await?),
        None => None,
    };
    let mut vars = if let Some(config) = config.as_deref() {
        Settings::detect_and_parse(config)
            .map(|settings| settings.template_vars)
            .unwrap_or_default()
    } else {
        BTreeMap::new()
    };
    for (key, value) in args {
        if key != "path" && key != "config" {
            vars.insert(key, value);
        }
    }
    let includes = load_template_includes(io, &template_path, &content).await?;
    Ok(CoreResponse::text(
        200,
        template::render_template_with_includes(&content, &vars, &includes),
    ))
}

async fn load_template_includes<I: PlatformIo>(
    io: &I,
    template_path: &str,
    content: &str,
) -> Result<BTreeMap<String, String>> {
    let mut includes = BTreeMap::new();
    let base_dir = template_path
        .rsplit_once(['/', '\\'])
        .map(|(dir, _)| dir)
        .unwrap_or("");
    for name in find_include_names(content) {
        if name.contains("..") || name.starts_with('/') || name.starts_with('\\') {
            continue;
        }
        let path = if base_dir.is_empty() {
            name.clone()
        } else {
            format!("{base_dir}/{name}")
        };
        if let Ok(included) = io.read_file(&path).await {
            includes.insert(name, included);
        }
    }
    Ok(includes)
}

fn find_include_names(content: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = content;
    while let Some(start) = rest.find("{%") {
        let after_start = &rest[start + 2..];
        let Some(end) = after_start.find("%}") else {
            break;
        };
        let tag = after_start[..end].trim();
        if let Some(name) = parse_include_name(tag) {
            names.push(name.to_string());
        }
        rest = &after_start[end + 2..];
    }
    names
}

fn parse_include_name(tag: &str) -> Option<&str> {
    let rest = tag.strip_prefix("include")?.trim();
    let quote = rest.as_bytes().first().copied()?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    let rest = &rest[1..];
    let end = rest.find(quote as char)?;
    Some(&rest[..end])
}

fn require_token(settings: &Settings, args: &BTreeMap<String, String>) -> Result<()> {
    if has_valid_token(settings, args) {
        Ok(())
    } else {
        Err(Error::Forbidden(
            "management access requires a configured token".to_string(),
        ))
    }
}

fn has_valid_token(settings: &Settings, args: &BTreeMap<String, String>) -> bool {
    !settings.api_access_token.is_empty()
        && args.get("token").is_some_and(|token| {
            constant_time_eq(token.as_bytes(), settings.api_access_token.as_bytes())
        })
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |diff, (left, right)| diff | (left ^ right))
        == 0
}

fn require_capability(enabled: bool, name: &str) -> Result<()> {
    if enabled {
        Ok(())
    } else {
        Err(Error::UnsupportedAdapterFeature(name.to_string()))
    }
}

fn require_local_access<I: PlatformIo>(
    io: &I,
    settings: &Settings,
    args: &BTreeMap<String, String>,
) -> Result<()> {
    if io.capabilities().trusted_local_files {
        Ok(())
    } else {
        require_token(settings, args)
    }
}

async fn fetch_remote<I: PlatformIo>(
    io: &I,
    settings: &Settings,
    url: &str,
    namespace: &str,
) -> Result<FetchedContent> {
    validate_remote_url(url, &settings.security)?;
    if let Some(cached) = io.cache_get(namespace, url).await? {
        return Ok(cached);
    }
    let mut request = FetchRequest::new(url);
    configure_fetch_request(&mut request, settings);
    let fetched = async {
        let fetched = io.fetch(&request).await?;
        if !(200..300).contains(&fetched.status) {
            return Err(Error::Upstream(format!(
                "{} returned HTTP {}",
                fetched.final_url, fetched.status
            )));
        }
        validate_remote_url(&fetched.final_url, &settings.security)?;
        Ok(fetched)
    }
    .await;
    let fetched = match fetched {
        Ok(fetched) => fetched,
        Err(err) if settings.serve_cache_on_fetch_fail => {
            if let Some(stale) = io.cache_get_stale(namespace, url).await? {
                return Ok(stale);
            }
            return Err(err);
        }
        Err(err) => return Err(err),
    };
    let ttl = match namespace {
        "ruleset" => settings.cache_ruleset_seconds,
        "config" => settings.cache_config_seconds,
        _ => settings.cache_subscription_seconds,
    };
    if ttl > 0 {
        io.cache_put(namespace, url, &fetched, ttl).await?;
    }
    Ok(fetched)
}

fn configure_fetch_request(request: &mut FetchRequest, settings: &Settings) {
    request.max_bytes = settings.security.max_download_bytes;
    request.connect_timeout_seconds = settings.security.connect_timeout_seconds;
    request.request_timeout_seconds = settings.security.request_timeout_seconds;
    request.max_redirects = settings.security.max_redirects;
    request.allow_private_network = settings.security.allow_private_network;
    request.allow_plain_http = settings.security.allow_plain_http;
    if !settings.security.upstream_user_agent.is_empty() {
        request.headers.insert(
            "User-Agent".to_string(),
            settings.security.upstream_user_agent.clone(),
        );
    }
}

fn validate_remote_url(raw: &str, security: &SecuritySettings) -> Result<()> {
    let parsed =
        url::Url::parse(raw).map_err(|err| Error::Forbidden(format!("invalid URL: {err}")))?;
    match parsed.scheme() {
        "https" => {}
        "http" if security.allow_plain_http => {}
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
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(Error::Forbidden(
            "credentials in upstream URLs are not allowed".to_string(),
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| Error::Forbidden("upstream URL has no host".to_string()))?;
    if !security.allow_private_network {
        let normalized = host.trim_end_matches('.').to_ascii_lowercase();
        if matches!(
            normalized.as_str(),
            "localhost"
                | "localhost.localdomain"
                | "metadata"
                | "metadata.google.internal"
                | "instance-data"
        ) || normalized.ends_with(".localhost")
        {
            return Err(Error::Forbidden(format!(
                "non-public upstream host is blocked: {host}"
            )));
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            validate_public_ip(ip)?;
        }
    }
    Ok(())
}

fn validate_public_ip(ip: IpAddr) -> Result<()> {
    let blocked = match ip {
        IpAddr::V4(ip) => is_blocked_ipv4(ip),
        IpAddr::V6(ip) => is_blocked_ipv6(ip),
    };
    if blocked {
        Err(Error::Forbidden(format!(
            "non-public upstream address is blocked: {ip}"
        )))
    } else {
        Ok(())
    }
}

fn is_blocked_ipv4(ip: Ipv4Addr) -> bool {
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
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 169 && octets[1] == 254)
}

fn is_blocked_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_blocked_ipv4(mapped);
    }
    let segments = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || segments[0] == 0x2001 && segments[1] == 0x0db8
}

fn validate_local_path(raw: &str, security: &SecuritySettings) -> Result<()> {
    if raw.is_empty() || raw.contains('\0') {
        return Err(Error::Forbidden("invalid local path".to_string()));
    }
    let path = Path::new(raw);
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(Error::Forbidden(
            "local path traversal is blocked".to_string(),
        ));
    }
    let allowed = security.allowed_local_roots.iter().any(|root| {
        let root = Path::new(root);
        if path.is_absolute() != root.is_absolute() {
            return false;
        }
        path.starts_with(root)
    });
    if !allowed {
        return Err(Error::Forbidden(format!(
            "local path is outside configured roots: {raw}"
        )));
    }
    Ok(())
}

fn validate_adapter_local_path<I: PlatformIo>(
    io: &I,
    raw: &str,
    security: &SecuritySettings,
) -> Result<()> {
    if io.capabilities().trusted_local_files {
        Ok(())
    } else {
        validate_local_path(raw, security)
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use crate::{AdapterCapabilities, MemoryIo};

    #[derive(Clone, Default)]
    struct TestIo {
        inner: MemoryIo,
        capabilities: AdapterCapabilities,
        fetched: Option<FetchedContent>,
        stale: Option<FetchedContent>,
        timeout: bool,
    }

    #[async_trait::async_trait]
    impl PlatformIo for TestIo {
        async fn fetch_url(&self, url: &str) -> Result<String> {
            self.inner.fetch_url(url).await
        }

        async fn fetch(&self, request: &FetchRequest) -> Result<FetchedContent> {
            if self.timeout {
                return Err(Error::Timeout("test timeout".to_string()));
            }
            if let Some(fetched) = &self.fetched {
                return Ok(fetched.clone());
            }
            self.inner.fetch(request).await
        }

        async fn read_file(&self, path: &str) -> Result<String> {
            self.inner.read_file(path).await
        }

        async fn write_file(&self, path: &str, content: &str, overwrite: bool) -> Result<()> {
            self.inner.write_file(path, content, overwrite).await
        }

        async fn flush_cache(&self) -> Result<()> {
            self.inner.flush_cache().await
        }

        async fn cache_get_stale(
            &self,
            _namespace: &str,
            _key: &str,
        ) -> Result<Option<FetchedContent>> {
            Ok(self.stale.clone())
        }

        fn capabilities(&self) -> AdapterCapabilities {
            self.capabilities
        }
    }

    #[tokio::test]
    async fn version_route_matches_legacy_shape() {
        let io = MemoryIo::default();
        let mut settings = Settings::default();
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/version".to_string(),
                query: String::new(),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;
        assert_eq!(response.status, 200);
        assert!(response.body.starts_with("subconverter v"));
        assert!(response.body.ends_with(" backend\n"));
    }

    #[test]
    fn remote_fetches_omit_user_agent_unless_configured() {
        let mut request = FetchRequest::new("https://example.com/subscription");
        configure_fetch_request(&mut request, &Settings::default());
        assert!(!request.headers.contains_key("User-Agent"));

        let mut settings = Settings::default();
        settings.security.upstream_user_agent = "SubscriptionClient/1.0".to_string();
        configure_fetch_request(&mut request, &settings);
        assert_eq!(
            request.headers.get("User-Agent").map(String::as_str),
            Some("SubscriptionClient/1.0")
        );
    }

    #[tokio::test]
    async fn sub_route_uploads_generated_content_when_requested() {
        let io = MemoryIo::default();
        let mut settings = Settings::default();
        let source = crate::util::url_safe_base64_encode(
            "ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#UploadNode",
        );
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: format!(
                    "target=surge&ver=4&upload=true&upload_path=managed.conf&url={source}"
                ),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        let uploads = io.uploads();
        assert_eq!(uploads.len(), 1);
        assert_eq!(uploads[0].name, "surge4");
        assert_eq!(uploads[0].path, "managed.conf");
        assert!(uploads[0].write_managed_url);
        assert!(uploads[0].content.contains("UploadNode"));
    }

    #[tokio::test]
    async fn token_protected_routes_reject_bad_token() {
        let io = MemoryIo::default();
        let mut settings = Settings {
            api_access_token: "secret".to_string(),
            ..Settings::default()
        };
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/flushcache".to_string(),
                query: "token=wrong".to_string(),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;
        assert_eq!(response.status, 403);
    }

    #[tokio::test]
    async fn readconf_reloads_existing_pref_file() {
        let io = MemoryIo::default().with_file(
            "pref.ini",
            "[common]\napi_access_token = new-token\napi_mode = true\n",
        );
        let mut settings = Settings {
            api_access_token: "old-token".to_string(),
            ..Settings::default()
        };
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/readconf".to_string(),
                query: "token=old-token".to_string(),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert_eq!(response.body, "done\n");
        assert_eq!(settings.api_access_token, "new-token");
        assert!(settings.api_mode);
    }

    #[tokio::test]
    async fn updateconf_writes_existing_pref_file_and_refreshes_settings() {
        let io = MemoryIo::default().with_file("pref.ini", "[common]\napi_mode = false\n");
        let mut settings = Settings {
            api_access_token: "old-token".to_string(),
            ..Settings::default()
        };
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Post,
                path: "/updateconf".to_string(),
                query: "type=direct&token=old-token".to_string(),
                body: "[common]\napi_mode = true\n".to_string(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert_eq!(response.body, "done\n");
        assert!(settings.api_mode);
        assert!(io
            .read_file("pref.ini")
            .await
            .expect("pref.ini should be updated")
            .contains("api_mode = true"));
        assert!(io.read_file("pref.toml").await.is_err());
    }

    #[tokio::test]
    async fn sub_route_fetches_remote_subscription_url() {
        let io = MemoryIo::default().with_url(
            "https://example.test/sub",
            "ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Example",
        );
        let mut settings = Settings::default();
        settings.api_mode = false;
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: "target=clash&url=https%3A%2F%2Fexample.test%2Fsub".to_string(),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;
        assert_eq!(response.status, 200);
        assert!(response.body.contains("name: Example"));
    }

    #[tokio::test]
    async fn get_route_fetches_remote_content_outside_api_mode() {
        let io = MemoryIo::default().with_url("https://example.test/plain.txt", "plain body");
        let mut settings = Settings::default();
        settings.api_mode = false;
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/get".to_string(),
                query: format!(
                    "url={}",
                    crate::util::url_encode("https://example.test/plain.txt")
                ),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert_eq!(response.body, "plain body");
    }

    #[tokio::test]
    async fn getlocal_route_reads_asset_content_outside_api_mode() {
        let io = MemoryIo::default().with_file("base/profile.tpl", "local body");
        let mut settings = Settings::default();
        settings.api_mode = false;
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/getlocal".to_string(),
                query: format!("path={}", crate::util::url_encode("base/profile.tpl")),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert_eq!(response.body, "local body");
    }

    #[tokio::test]
    async fn get_and_getlocal_routes_are_disabled_in_api_mode() {
        let io = MemoryIo::default()
            .with_url("https://example.test/plain.txt", "plain body")
            .with_file("base/profile.tpl", "local body");
        let mut settings = Settings {
            api_mode: true,
            ..Settings::default()
        };

        let get_response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/get".to_string(),
                query: format!(
                    "url={}",
                    crate::util::url_encode("https://example.test/plain.txt")
                ),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;
        let getlocal_response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/getlocal".to_string(),
                query: format!("path={}", crate::util::url_encode("base/profile.tpl")),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(get_response.status, 404);
        assert_eq!(getlocal_response.status, 404);
    }

    #[tokio::test]
    async fn sub_route_forwards_subscription_userinfo_header() {
        let io = MemoryIo::default()
            .with_url(
                "https://example.test/sub",
                "ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Example",
            )
            .with_url_header(
                "https://example.test/sub",
                "Subscription-UserInfo",
                "upload=1; download=2; total=3; expire=4",
            );
        let mut settings = Settings::default();
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: "target=clash&url=https%3A%2F%2Fexample.test%2Fsub".to_string(),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;
        assert_eq!(response.status, 200);
        assert_eq!(
            response.headers.get("Subscription-UserInfo"),
            Some(&"upload=1; download=2; total=3; expire=4".to_string())
        );
    }

    #[tokio::test]
    async fn sub_route_honors_append_sub_userinfo_config_and_override() {
        let io = MemoryIo::default()
            .with_file("pref.ini", "[node_pref]\nappend_sub_userinfo=false\n")
            .with_url(
                "https://example.test/sub",
                "ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Example",
            )
            .with_url_header(
                "https://example.test/sub",
                "Subscription-UserInfo",
                "upload=1; download=2; total=3; expire=4",
            );
        let mut settings = Settings::default();
        let disabled = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: "target=clash&url=https%3A%2F%2Fexample.test%2Fsub&config=pref.ini"
                    .to_string(),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(disabled.status, 200);
        assert!(!disabled.headers.contains_key("Subscription-UserInfo"));

        let enabled = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: "target=clash&url=https%3A%2F%2Fexample.test%2Fsub&config=pref.ini&append_info=true"
                    .to_string(),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(enabled.status, 200);
        assert_eq!(
            enabled.headers.get("Subscription-UserInfo"),
            Some(&"upload=1; download=2; total=3; expire=4".to_string())
        );
    }

    #[tokio::test]
    async fn sub_route_derives_subscription_userinfo_from_node_remarks() {
        let io = MemoryIo::default().with_file(
            "pref.ini",
            "[userinfo]\nstream_rule=^Bandwidth: (.*?)/(.*)$|used=$1&total=$2\n",
        );
        let mut settings = Settings::default();
        let source = "ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Bandwidth%3A%201GB%2F10GB";
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: format!(
                    "target=clash&url={}&config=pref.ini",
                    crate::util::url_encode(source)
                ),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert_eq!(
            response.headers.get("Subscription-UserInfo"),
            Some(&"upload=0; download=1073741824; total=10737418240;".to_string())
        );
    }

    #[tokio::test]
    async fn sub_route_uses_injected_time_for_subscription_expiry() {
        let io = MemoryIo::default().with_file(
            "pref.ini",
            "[userinfo]\ntime_rule=^Expires: (.*)$|left=$1\n",
        );
        let mut settings = Settings::default();
        let source = "ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Expires%3A%202d";
        let response = handle_request_with_context(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: format!(
                    "target=clash&url={}&config=pref.ini",
                    crate::util::url_encode(source)
                ),
                body: String::new(),
                headers: BTreeMap::new(),
            },
            RuntimeContext::deterministic(1_000, 7),
        )
        .await;

        assert_eq!(response.status, 200);
        assert_eq!(
            response.headers.get("Subscription-UserInfo"),
            Some(&"upload=0; download=0; total=0; expire=173800;".to_string())
        );
    }

    #[tokio::test]
    async fn sub_route_accepts_modern_protocol_direct_links() {
        let io = MemoryIo::default();
        let mut settings = Settings::default();
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: "target=clash&url=snell%3A%2F%2Fsecret%40snell.example.com%3A44046%3Fversion%3D3%23Snell".to_string(),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;
        assert_eq!(response.status, 200);
        assert!(response.body.contains("name: Snell"));
        assert!(response.body.contains("type: snell"));
        assert!(response.body.contains("psk: secret"));
    }

    #[tokio::test]
    async fn sub_route_applies_request_node_options() {
        let io = MemoryIo::default();
        let mut settings = Settings::default();
        let source = [
            "ss://YWVzLTEyOC1nY206cGFzcw==@b.example.com:8388#Beta",
            "ss://YWVzLTEyOC1nY206cGFzcw==@a.example.com:8388#Alpha",
            "ss://YWVzLTEyOC1nY206cGFzcw==@c.example.com:8388#Drop",
        ]
        .join("|");
        let query = format!(
            "target=clash&url={}&include=Alpha%7CBeta&exclude=Drop&rename=Alpha%40Renamed&append_type=true&sort=true&udp=false&tfo=true&scv=true&tls13=true&list=true",
            crate::util::url_encode(&source)
        );
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query,
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert!(response.body.contains("proxies:"));
        assert!(!response.body.contains("proxy-groups:"));
        assert!(response.body.contains("name: '[SS] Beta'"));
        assert!(response.body.contains("name: '[SS] Renamed'"));
        assert!(!response.body.contains("Drop"));
        assert!(response.body.contains("udp: false"));
        assert!(response.body.contains("tfo: true"));
        assert!(response.body.contains("skip-cert-verify: true"));
        assert!(response.body.contains("tls13: true"));
        assert!(
            response.body.find("[SS] Beta").expect("Beta should exist")
                < response
                    .body
                    .find("[SS] Renamed")
                    .expect("Renamed should exist")
        );
    }

    #[tokio::test]
    async fn sub_route_applies_configured_node_option_defaults() {
        let io = MemoryIo::default().with_file(
            "pref.ini",
            "[common]\nappend_proxy_type=true\n[node_pref]\nsort_flag=true\nudp_flag=false\ntcp_fast_open_flag=true\nskip_cert_verify_flag=true\ntls13_flag=true\n",
        );
        let mut settings = Settings::default();
        let source = [
            "ss://YWVzLTEyOC1nY206cGFzcw==@b.example.com:8388#Beta",
            "ss://YWVzLTEyOC1nY206cGFzcw==@a.example.com:8388#Alpha",
        ]
        .join("|");
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: format!(
                    "target=clash&url={}&config=pref.ini&list=true",
                    crate::util::url_encode(&source)
                ),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert!(response.body.contains("name: '[SS] Alpha'"));
        assert!(response.body.contains("name: '[SS] Beta'"));
        assert!(
            response.body.find("[SS] Alpha").expect("alpha exists")
                < response.body.find("[SS] Beta").expect("beta exists")
        );
        assert!(response.body.contains("udp: false"));
        assert!(response.body.contains("tfo: true"));
        assert!(response.body.contains("skip-cert-verify: true"));
        assert!(response.body.contains("tls13: true"));
    }

    #[tokio::test]
    async fn sub_route_request_node_options_override_config_defaults() {
        let io = MemoryIo::default().with_file("pref.toml", "[common]\nappend_proxy_type = true\n");
        let mut settings = Settings::default();
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: format!(
                    "target=clash&url={}&config=pref.toml&append_type=false",
                    crate::util::url_encode("ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Alpha")
                ),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert!(response.body.contains("name: Alpha"));
        assert!(!response.body.contains("[SS] Alpha"));
    }

    #[tokio::test]
    async fn sub_route_group_argument_overrides_node_group() {
        let io = MemoryIo::default().with_file(
            "pref.ini",
            "[rulesets]\ncustom_proxy_group=OnlyCustom`select`!!GROUP=Custom\n",
        );
        let mut settings = Settings::default();
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: format!(
                    "target=clash&url={}&config=pref.ini&group=Custom",
                    crate::util::url_encode("ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Alpha")
                ),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert!(response.body.contains("name: OnlyCustom"));
        assert!(response.body.contains("- Alpha"));
    }

    #[tokio::test]
    async fn sub_route_filters_deprecated_clash_nodes_by_default() {
        let io = MemoryIo::default();
        let mut settings = Settings::default();
        let source = [
            "ss://Y2hhY2hhMjA6cGFzcw==@deprecated.example.com:8388#Deprecated",
            "ss://YWVzLTEyOC1nY206cGFzcw==@keep.example.com:8388#Keep",
        ]
        .join("|");
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: format!("target=clash&url={}", crate::util::url_encode(&source)),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert!(response.body.contains("name: Keep"));
        assert!(!response.body.contains("Deprecated"));
        assert!(!response.body.contains("deprecated.example.com"));
    }

    #[tokio::test]
    async fn sub_route_can_disable_deprecated_node_filter() {
        let io = MemoryIo::default();
        let mut settings = Settings::default();
        let source = [
            "ss://Y2hhY2hhMjA6cGFzcw==@deprecated.example.com:8388#Deprecated",
            "ss://YWVzLTEyOC1nY206cGFzcw==@keep.example.com:8388#Keep",
        ]
        .join("|");
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: format!(
                    "target=clash&url={}&fdn=false",
                    crate::util::url_encode(&source)
                ),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert!(response.body.contains("name: Deprecated"));
        assert!(response.body.contains("deprecated.example.com"));
    }

    #[tokio::test]
    async fn sub_route_applies_inline_groups_and_rulesets() {
        let io = MemoryIo::default();
        let mut settings = Settings::default();
        let group = crate::util::url_safe_base64_encode(
            "Auto`url-test`.*`http://www.gstatic.com/generate_204`300",
        );
        let ruleset = crate::util::url_safe_base64_encode("DIRECT,[]GEOIP,CN@Auto,[]FINAL");
        let query = format!(
            "target=clash&url={}&groups={group}&ruleset={ruleset}",
            crate::util::url_encode("ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Alpha")
        );
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query,
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert!(response.body.contains("name: Auto"));
        assert!(response.body.contains("type: url-test"));
        assert!(response
            .body
            .contains("url: http://www.gstatic.com/generate_204"));
        assert!(response.body.contains("GEOIP,CN,DIRECT"));
        assert!(response.body.contains("MATCH,Auto"));
    }

    #[tokio::test]
    async fn sub_route_uses_managed_getruleset_urls_when_rulesets_are_not_expanded() {
        let io = MemoryIo::default().with_file(
            "pref.toml",
            r#"
[managed_config]
managed_config_prefix = "https://sub.example.test"

[[rulesets]]
group = "Proxy"
ruleset = "https://rules.example.test/domain.list"
type = "clash-domain"
interval = 3600
"#,
        );
        let mut settings = Settings::default();
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: format!(
                    "target=clash&url={}&config=pref.toml&expand=false",
                    crate::util::url_encode("ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Alpha")
                ),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert!(response.body.contains("- RULE-SET,domain.list,Proxy"));
        assert!(response.body.contains("rule-providers:"));
        assert!(response.body.contains("domain.list:"));
        assert!(response.body.contains("behavior: domain"));
        assert!(response.body.contains(
            "url: https://sub.example.test/getruleset?type=3&url=Y2xhc2gtZG9tYWluOmh0dHBzOi8vcnVsZXMuZXhhbXBsZS50ZXN0L2RvbWFpbi5saXN0"
        ));
        assert!(response.body.contains("path: ./providers/"));
        assert!(response.body.contains("interval: 3600"));
    }

    #[tokio::test]
    async fn sub_route_classic_arg_forces_classical_clash_rule_provider() {
        let io = MemoryIo::default().with_file(
            "pref.toml",
            r#"
[managed_config]
managed_config_prefix = "https://sub.example.test"

[[rulesets]]
group = "Proxy"
ruleset = "https://rules.example.test/domain.list"
type = "clash-domain"
"#,
        );
        let mut settings = Settings::default();
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: format!(
                    "target=clash&url={}&config=pref.toml&expand=false&classic=true",
                    crate::util::url_encode("ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Alpha")
                ),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert!(response.body.contains("- RULE-SET,domain.list,Proxy"));
        assert!(response.body.contains("behavior: classical"));
        assert!(response.body.contains(
            "url: https://sub.example.test/getruleset?type=6&url=Y2xhc2gtZG9tYWluOmh0dHBzOi8vcnVsZXMuZXhhbXBsZS50ZXN0L2RvbWFpbi5saXN0"
        ));
    }

    #[tokio::test]
    async fn sub_route_prepends_insert_url_from_config() {
        let io = MemoryIo::default().with_file(
            "pref.ini",
            "[common]\nenable_insert=true\ninsert_url=ss://YWVzLTEyOC1nY206cGFzcw==@insert.example.com:8388#Inserted\nprepend_insert_url=true\n",
        );
        let mut settings = Settings::default();
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: format!(
                    "target=clash&url={}&config=pref.ini",
                    crate::util::url_encode(
                        "ss://YWVzLTEyOC1nY206cGFzcw==@main.example.com:8388#Main"
                    )
                ),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert!(
            response.body.find("name: Inserted").expect("insert exists")
                < response.body.find("name: Main").expect("main exists")
        );
        assert!(response.body.contains("server: insert.example.com"));
        assert!(response.body.contains("server: main.example.com"));
    }

    #[tokio::test]
    async fn sub_route_can_append_insert_url_with_request_override() {
        let io = MemoryIo::default().with_file(
            "pref.toml",
            r#"
[common]
enable_insert = true
insert_url = "ss://YWVzLTEyOC1nY206cGFzcw==@insert.example.com:8388#Inserted"
prepend_insert_url = true
"#,
        );
        let mut settings = Settings::default();
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: format!(
                    "target=clash&url={}&config=pref.toml&prepend=false",
                    crate::util::url_encode(
                        "ss://YWVzLTEyOC1nY206cGFzcw==@main.example.com:8388#Main"
                    )
                ),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert!(
            response.body.find("name: Main").expect("main exists")
                < response.body.find("name: Inserted").expect("insert exists")
        );
    }

    #[tokio::test]
    async fn sub_route_allows_insert_url_without_url_argument() {
        let io = MemoryIo::default().with_file(
            "pref.yml",
            r#"
common:
  enable_insert: true
  insert_url:
  - ss://YWVzLTEyOC1nY206cGFzcw==@insert.example.com:8388#Inserted
"#,
        );
        let mut settings = Settings::default();
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: "target=clash&config=pref.yml".to_string(),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert!(response.body.contains("name: Inserted"));
        assert!(response.body.contains("server: insert.example.com"));
    }

    #[tokio::test]
    async fn sub_route_uses_default_url_when_url_argument_is_missing() {
        let io = MemoryIo::default().with_file(
            "pref.yml",
            r#"
common:
  default_url:
  - ss://YWVzLTEyOC1nY206cGFzcw==@default.example.com:8388#Default
"#,
        );
        let mut settings = Settings::default();
        settings.api_mode = false;
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: "target=clash&config=pref.yml".to_string(),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert!(response.body.contains("name: Default"));
        assert!(response.body.contains("server: default.example.com"));
    }

    #[tokio::test]
    async fn sub_route_requires_api_token_before_using_default_url() {
        let io = MemoryIo::default().with_file(
            "pref.ini",
            "[common]\napi_mode=true\napi_access_token=secret\ndefault_url=ss://YWVzLTEyOC1nY206cGFzcw==@default.example.com:8388#Default\n",
        );
        let mut settings = Settings::default();
        let denied = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: "target=clash&config=pref.ini".to_string(),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(denied.status, 400);
        assert!(denied.body.contains("missing required argument: url"));

        let allowed = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: "target=clash&config=pref.ini&token=secret".to_string(),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(allowed.status, 200);
        assert!(allowed.body.contains("name: Default"));
    }

    #[tokio::test]
    async fn sub_route_sets_compatible_response_headers() {
        let io = MemoryIo::default();
        let mut settings = Settings::default();
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: format!(
                    "target=clash&url={}&interval=7200&filename=profile.yaml",
                    crate::util::url_encode("ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Alpha")
                ),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert_eq!(
            response.headers.get("profile-update-interval"),
            Some(&"2".to_string())
        );
        assert_eq!(
            response.headers.get("content-disposition"),
            Some(
                &"attachment; filename=\"profile.yaml\"; filename*=utf-8''profile%2Eyaml"
                    .to_string()
            )
        );
    }

    #[tokio::test]
    async fn sub_route_adds_managed_config_prefix_for_surge() {
        let io = MemoryIo::default();
        let mut settings = Settings {
            managed_config_prefix: "https://sub.example.test".to_string(),
            write_managed_config: true,
            config_update_interval: 3600,
            config_update_strict: true,
            ..Settings::default()
        };
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: format!(
                    "target=surge&url={}",
                    crate::util::url_encode("ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Alpha")
                ),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert!(response
            .body
            .starts_with("#!MANAGED-CONFIG https://sub.example.test/sub?target=surge"));
        assert!(response.body.contains(" interval=3600 strict=true\n\n"));
        assert!(response.body.contains("[Proxy]"));
    }

    #[tokio::test]
    async fn sub_route_request_managed_interval_overrides_config_default() {
        let io = MemoryIo::default();
        let mut settings = Settings {
            managed_config_prefix: "https://sub.example.test".to_string(),
            write_managed_config: true,
            config_update_interval: 3600,
            config_update_strict: true,
            ..Settings::default()
        };
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: format!(
                    "target=surge&interval=7200&strict=false&url={}",
                    crate::util::url_encode("ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Alpha")
                ),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert!(response.body.contains(" interval=7200 strict=false\n\n"));
    }

    #[tokio::test]
    async fn sub_route_skips_managed_config_prefix_for_nodelist() {
        let io = MemoryIo::default();
        let mut settings = Settings {
            managed_config_prefix: "https://sub.example.test".to_string(),
            write_managed_config: true,
            ..Settings::default()
        };
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: format!(
                    "target=surge&list=true&url={}",
                    crate::util::url_encode("ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Alpha")
                ),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert!(!response.body.starts_with("#!MANAGED-CONFIG"));
    }

    #[tokio::test]
    async fn sub_route_auto_target_uses_user_agent() {
        let io = MemoryIo::default();
        let mut settings = Settings::default();
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: format!(
                    "target=auto&url={}",
                    crate::util::url_encode("ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Alpha")
                ),
                body: String::new(),
                headers: BTreeMap::from([(
                    "User-Agent".to_string(),
                    "Quantumult%20X/1.0".to_string(),
                )]),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert!(response.body.contains("shadowsocks = example.com"));
    }

    #[tokio::test]
    async fn getprofile_parses_profile_and_converts_subscription() {
        let io = MemoryIo::default().with_file(
            "base/profiles/demo.ini",
            "[Profile]\ntarget=clash\nurl=ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#ProfileNode\nrename=Profile@Managed\n",
        );
        let mut settings = Settings {
            api_access_token: "secret".to_string(),
            ..Settings::default()
        };
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/getprofile".to_string(),
                query: "name=demo&token=secret".to_string(),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert!(response.body.contains("name: ManagedNode"));
        assert!(response.body.contains("server: example.com"));
    }

    #[tokio::test]
    async fn getprofile_merges_multiple_profiles() {
        let io = MemoryIo::default()
            .with_file(
                "base/profiles/one.ini",
                "[Profile]\ntarget=clash\nurl=ss://YWVzLTEyOC1nY206cGFzcw==@one.example.com:8388#One\nrename=One@Primary\nrename=Primary@Renamed\n",
            )
            .with_file(
                "base/profiles/two.ini",
                "[Profile]\nurl=ss://YWVzLTEyOC1nY206cGFzcw==@two.example.com:8388#Two\n",
            );
        let mut settings = Settings {
            api_access_token: "secret".to_string(),
            ..Settings::default()
        };
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/getprofile".to_string(),
                query: "name=one%7Ctwo&token=secret".to_string(),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert!(response.body.contains("name: Renamed"));
        assert!(response.body.contains("server: one.example.com"));
        assert!(response.body.contains("name: Two"));
        assert!(response.body.contains("server: two.example.com"));
    }

    #[tokio::test]
    async fn getprofile_rejects_wrong_token() {
        let io = MemoryIo::default().with_file(
            "base/profiles/demo.ini",
            "[Profile]\ntarget=clash\nurl=ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#ProfileNode\n",
        );
        let mut settings = Settings {
            api_access_token: "secret".to_string(),
            ..Settings::default()
        };
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/getprofile".to_string(),
                query: "name=demo&token=wrong".to_string(),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 403);
    }

    #[tokio::test]
    async fn sub_route_fetches_remote_config_url() {
        let io = MemoryIo::default()
            .with_url(
                "https://example.test/sub",
                "ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#HK%20Node",
            )
            .with_url(
                "https://example.test/config.ini",
                "[node_pref]\nrename_node = HK@Hong Kong\n[emojis]\nadd_emoji=true\nemoji = Hong Kong,HK\n",
            );
        let mut settings = Settings::default();
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: "target=clash&url=https%3A%2F%2Fexample.test%2Fsub&config=https%3A%2F%2Fexample.test%2Fconfig.ini".to_string(),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;
        assert_eq!(response.status, 200);
        assert!(response.body.contains("name: HK Hong Kong Node"));
    }

    #[tokio::test]
    async fn sub_route_uses_default_external_config_when_config_arg_is_missing() {
        let io = MemoryIo::default().with_file(
            "config/default.ini",
            "[node_pref]\nrename_node = Default@FromDefault\n",
        );
        let mut settings = Settings {
            default_external_config: "config/default.ini".to_string(),
            ..Settings::default()
        };
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: format!(
                    "target=clash&url={}",
                    crate::util::url_encode(
                        "ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Default"
                    )
                ),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert!(response.body.contains("name: FromDefault"));
    }

    #[tokio::test]
    async fn sub_route_config_arg_overrides_default_external_config() {
        let io = MemoryIo::default()
            .with_file(
                "config/default.ini",
                "[node_pref]\nrename_node = Node@Default\n",
            )
            .with_file(
                "config/explicit.ini",
                "[node_pref]\nrename_node = Node@Explicit\n",
            );
        let mut settings = Settings {
            default_external_config: "config/default.ini".to_string(),
            ..Settings::default()
        };
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: format!(
                    "target=clash&config={}&url={}",
                    crate::util::url_encode("config/explicit.ini"),
                    crate::util::url_encode("ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Node")
                ),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;

        assert_eq!(response.status, 200);
        assert!(response.body.contains("name: Explicit"));
        assert!(!response.body.contains("name: Default"));
    }

    #[tokio::test]
    async fn sub_route_resolves_config_referenced_clash_base() {
        let io = MemoryIo::default()
            .with_url(
                "https://example.test/sub",
                "ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#NodeA",
            )
            .with_url(
                "https://example.test/config.toml",
                "clash_rule_base = \"base.yml\"\n",
            )
            .with_file("base.yml", "mixed-port: 7890\nmode: Rule\n");
        let mut settings = Settings::default();
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: "target=clash&url=https%3A%2F%2Fexample.test%2Fsub&config=https%3A%2F%2Fexample.test%2Fconfig.toml".to_string(),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;
        assert_eq!(response.status, 200);
        assert!(response.body.contains("mixed-port"));
        assert!(response.body.contains("7890"));
        assert!(response.body.contains("name: NodeA"));
    }

    #[tokio::test]
    async fn resolve_config_content_expands_all_rule_base_references() {
        let io = MemoryIo::default().with_file("base/surge.conf", "[General]\nloglevel = notify\n");
        let settings = Settings::default();

        let toml = resolve_config_content(
            &io,
            &settings,
            "surge_rule_base = \"base/surge.conf\"\n",
            true,
        )
        .await
        .expect("toml config should resolve");
        let toml_settings = Settings::detect_and_parse(&toml).expect("toml should parse");
        assert!(toml_settings.surge_rule_base.contains("[General]"));
        assert!(!toml_settings.surge_rule_base.contains("surge.conf"));

        let yaml = resolve_config_content(
            &io,
            &settings,
            "common:\n  surge_rule_base: base/surge.conf\n",
            true,
        )
        .await
        .expect("yaml config should resolve");
        let yaml_settings = Settings::detect_and_parse(&yaml).expect("yaml should parse");
        assert!(yaml_settings.surge_rule_base.contains("loglevel = notify"));
        assert!(!yaml_settings.surge_rule_base.contains("surge.conf"));

        let ini = resolve_config_content(
            &io,
            &settings,
            "[common]\nsurge_rule_base=base/surge.conf\n",
            true,
        )
        .await
        .expect("ini config should resolve");
        let ini_settings = Settings::detect_and_parse(&ini).expect("ini should parse");
        assert!(ini_settings.surge_rule_base.contains("[General]"));
        assert!(!ini_settings.surge_rule_base.contains("surge.conf"));
    }

    #[tokio::test]
    async fn sub_route_expands_yaml_config_imports() {
        let io = MemoryIo::default()
            .with_file(
                "sub.txt",
                "ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#NodeA",
            )
            .with_file(
                "pref.yml",
                r#"
rulesets:
  rulesets:
  - {import: rulesets.txt}
"#,
            )
            .with_file("rulesets.txt", "DIRECT,[]GEOIP,CN\nProxy,[]FINAL\n");
        let mut settings = Settings::default();
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: "target=clash&url=sub.txt&config=pref.yml".to_string(),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;
        assert_eq!(response.status, 200);
        assert!(response.body.contains("name: NodeA"));
        assert!(response.body.contains("GEOIP,CN,DIRECT"));
        assert!(response.body.contains("MATCH,Proxy"));
    }

    #[tokio::test]
    async fn getruleset_outputs_clash_domain_provider() {
        let io = MemoryIo::default().with_file(
            "rules.list",
            "DOMAIN,example.com,Proxy\nDOMAIN-SUFFIX,example.org,Proxy\nIP-CIDR,1.1.1.0/24,Proxy\n",
        );
        let mut settings = Settings::default();
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/getruleset".to_string(),
                query: format!(
                    "type=3&url={}",
                    crate::util::url_safe_base64_encode("rules.list")
                ),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;
        assert_eq!(response.status, 200);
        assert!(response.body.contains("payload:"));
        assert!(response.body.contains("example.com"));
        assert!(response.body.contains(".example.org"));
        assert!(!response.body.contains("1.1.1.0/24"));
    }

    #[tokio::test]
    async fn getruleset_outputs_quanx_group_rules() {
        let io = MemoryIo::default().with_file(
            "rules.list",
            "DOMAIN,example.com\nIP-CIDR6,::1/128,no-resolve\n",
        );
        let mut settings = Settings::default();
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/getruleset".to_string(),
                query: format!(
                    "type=2&url={}&group={}",
                    crate::util::url_safe_base64_encode("rules.list"),
                    crate::util::url_safe_base64_encode("Proxy")
                ),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;
        assert_eq!(response.status, 200);
        assert!(response.body.contains("DOMAIN,example.com,Proxy"));
        assert!(response.body.contains("IP6-CIDR,::1/128,Proxy"));
    }

    #[tokio::test]
    async fn getruleset_outputs_ip_and_classical_providers() {
        let io = MemoryIo::default().with_file(
            "rules.list",
            "DOMAIN,example.com,Proxy\nIP-CIDR,1.1.1.0/24,Proxy\nIP-CIDR6,::1/128,Proxy\n",
        );
        let mut settings = Settings::default();
        let ip_response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/getruleset".to_string(),
                query: format!(
                    "type=4&url={}",
                    crate::util::url_safe_base64_encode("rules.list")
                ),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;
        assert_eq!(ip_response.status, 200);
        assert!(ip_response.body.contains("1.1.1.0/24"));
        assert!(ip_response.body.contains("::1/128"));
        assert!(!ip_response.body.contains("example.com"));

        let classical_response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/getruleset".to_string(),
                query: format!(
                    "type=6&url={}",
                    crate::util::url_safe_base64_encode("rules.list")
                ),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;
        assert_eq!(classical_response.status, 200);
        assert!(classical_response.body.contains("DOMAIN,example.com,Proxy"));
        assert!(classical_response.body.contains("IP-CIDR,1.1.1.0/24,Proxy"));
    }

    #[tokio::test]
    async fn render_route_applies_template_globals_and_query_vars() {
        let io = MemoryIo::default()
            .with_file(
                "templates/demo.tpl",
                "{{ title }} {{ name }} {{ managed_config_prefix }}",
            )
            .with_file(
                "pref.toml",
                r#"
[managed_config]
managed_config_prefix = "http://127.0.0.1:25500"

[template]
template_path = "templates"

[[template.globals]]
key = "title"
value = "Hello"
"#,
            );
        let mut settings = Settings::default();
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/render".to_string(),
                query: "path=templates%2Fdemo.tpl&config=pref.toml&name=Rust".to_string(),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;
        assert_eq!(response.status, 200);
        assert_eq!(response.body, "Hello Rust http://127.0.0.1:25500");
    }

    #[tokio::test]
    async fn render_route_expands_relative_includes() {
        let io = MemoryIo::default()
            .with_file(
                "templates/main.tpl",
                "before {% include \"child.tpl\" %} after",
            )
            .with_file("templates/child.tpl", "{{ name }}");
        let mut settings = Settings::default();
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/render".to_string(),
                query: "path=templates%2Fmain.tpl&name=Rust".to_string(),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;
        assert_eq!(response.status, 200);
        assert_eq!(response.body, "before Rust after");
    }

    #[tokio::test]
    async fn secure_fetch_policy_maps_rejections_and_upstream_failures() {
        let mut settings = Settings::default();
        let io = MemoryIo::default();
        for url in ["http://example.com/sub", "https://127.0.0.1/sub"] {
            let response = handle_request(
                &io,
                &mut settings,
                CoreRequest {
                    method: Method::Get,
                    path: "/sub".to_string(),
                    query: format!("target=clash&url={}", crate::util::url_encode(url)),
                    body: String::new(),
                    headers: BTreeMap::new(),
                },
            )
            .await;
            assert_eq!(response.status, 403, "{url}");
        }

        settings.security.max_download_bytes = 8;
        let url = "https://example.com/oversized";
        let io = MemoryIo::default().with_url(url, "x".repeat(9));
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: format!("target=clash&url={}", crate::util::url_encode(url)),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;
        assert_eq!(response.status, 413);

        let io = TestIo {
            fetched: Some(FetchedContent {
                status: 503,
                final_url: "https://example.com/sub".to_string(),
                ..FetchedContent::default()
            }),
            ..TestIo::default()
        };
        let response = handle_request(
            &io,
            &mut Settings::default(),
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: "target=clash&url=https%3A%2F%2Fexample.com%2Fsub".to_string(),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;
        assert_eq!(response.status, 502);

        let io = TestIo {
            timeout: true,
            ..TestIo::default()
        };
        let response = handle_request(
            &io,
            &mut Settings::default(),
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: "target=clash&url=https%3A%2F%2Fexample.com%2Fsub".to_string(),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;
        assert_eq!(response.status, 504);
    }

    #[tokio::test]
    async fn stale_subscription_cache_is_used_only_when_enabled() {
        let stale = FetchedContent {
            body: "ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Cached".to_string(),
            status: 200,
            final_url: "https://example.com/sub".to_string(),
            ..FetchedContent::default()
        };
        let io = TestIo {
            stale: Some(stale),
            timeout: true,
            ..TestIo::default()
        };
        let request = CoreRequest {
            method: Method::Get,
            path: "/sub".to_string(),
            query: "target=clash&url=https%3A%2F%2Fexample.com%2Fsub".to_string(),
            body: String::new(),
            headers: BTreeMap::new(),
        };

        let disabled = handle_request(&io, &mut Settings::default(), request.clone()).await;
        assert_eq!(disabled.status, 504);

        let mut settings = Settings {
            serve_cache_on_fetch_fail: true,
            ..Settings::default()
        };
        let enabled = handle_request(&io, &mut settings, request).await;
        assert_eq!(enabled.status, 200);
        assert!(enabled.body.contains("name: Cached"));
    }

    #[tokio::test]
    async fn worker_capability_subset_returns_stable_not_implemented() {
        let capabilities = AdapterCapabilities {
            persistent_config: false,
            cache_management: false,
            local_files: true,
            trusted_local_files: false,
            raw_fetch_routes: false,
            local_management_routes: false,
            scripts: false,
            cron: false,
            gist_upload: false,
        };
        let io = TestIo {
            capabilities,
            ..TestIo::default()
        };
        let cases = [
            (Method::Get, "/refreshrules", ""),
            (Method::Get, "/readconf", ""),
            (Method::Post, "/updateconf", "type=direct"),
            (Method::Get, "/flushcache", ""),
            (Method::Get, "/get", "url=https%3A%2F%2Fexample.com"),
            (Method::Get, "/getlocal", "path=base%2Fdemo.txt"),
        ];
        for (method, path, query) in cases {
            let response = handle_request(
                &io,
                &mut Settings::default(),
                CoreRequest {
                    method,
                    path: path.to_string(),
                    query: query.to_string(),
                    body: String::new(),
                    headers: BTreeMap::new(),
                },
            )
            .await;
            assert_eq!(response.status, 501, "{path}");
        }

        let source = crate::util::url_encode("ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Node");
        let filter = crate::util::url_encode("function filter() { return true; }");
        let response = handle_request(
            &io,
            &mut Settings::default(),
            CoreRequest {
                method: Method::Get,
                path: "/sub".to_string(),
                query: format!("target=clash&url={source}&filter_script={filter}"),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;
        assert_eq!(response.status, 501);
    }

    #[tokio::test]
    async fn management_requires_a_non_empty_matching_token() {
        let io = MemoryIo::default();
        let response = handle_request(
            &io,
            &mut Settings::default(),
            CoreRequest {
                method: Method::Get,
                path: "/flushcache".to_string(),
                query: "token=".to_string(),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;
        assert_eq!(response.status, 403);
    }

    #[tokio::test]
    async fn head_responses_are_empty_for_success_and_error() {
        let source = crate::util::url_encode("ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Node");
        for query in [format!("target=clash&url={source}"), String::new()] {
            let response = handle_request(
                &MemoryIo::default(),
                &mut Settings::default(),
                CoreRequest {
                    method: Method::Head,
                    path: "/sub".to_string(),
                    query,
                    body: String::new(),
                    headers: BTreeMap::new(),
                },
            )
            .await;
            assert!(matches!(response.status, 200 | 400));
            assert!(response.body.is_empty());
            assert_eq!(response.content_type, "text/plain");
        }
    }

    #[tokio::test]
    async fn getlocal_rejects_path_traversal_after_token_check() {
        let io = TestIo::default();
        let mut settings = Settings {
            api_mode: false,
            api_access_token: "secret".to_string(),
            ..Settings::default()
        };
        let response = handle_request(
            &io,
            &mut settings,
            CoreRequest {
                method: Method::Get,
                path: "/getlocal".to_string(),
                query: "path=..%2Fsecret.txt&token=secret".to_string(),
                body: String::new(),
                headers: BTreeMap::new(),
            },
        )
        .await;
        assert_eq!(response.status, 403);
    }
}
