use regex::Regex;
use std::fmt;
use std::str::FromStr;
#[cfg(feature = "quickjs")]
use std::time::{Duration, Instant};
#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Settings;
use crate::model::RegexMatchConfig;
use crate::model::{Proxy, ProxyType, TriBool};
use crate::util::{base64_decode, base64_encode, split_sources, url_safe_base64_encode};
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Clash,
    ClashR,
    Quan,
    QuanX,
    Loon,
    Shadowsocks,
    ShadowsocksSub,
    Ssd,
    ShadowsocksR,
    Surfboard,
    Surge,
    Mellow,
    V2Ray,
    Trojan,
    SingBox,
    Mixed,
}

impl Target {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "clash" => Ok(Self::Clash),
            "clashr" => Ok(Self::ClashR),
            "quan" => Ok(Self::Quan),
            "quanx" => Ok(Self::QuanX),
            "loon" => Ok(Self::Loon),
            "ss" => Ok(Self::Shadowsocks),
            "sssub" => Ok(Self::ShadowsocksSub),
            "ssd" => Ok(Self::Ssd),
            "ssr" => Ok(Self::ShadowsocksR),
            "surfboard" => Ok(Self::Surfboard),
            "surge" => Ok(Self::Surge),
            "mellow" => Ok(Self::Mellow),
            "v2ray" => Ok(Self::V2Ray),
            "trojan" => Ok(Self::Trojan),
            "singbox" => Ok(Self::SingBox),
            "mixed" => Ok(Self::Mixed),
            other => Err(Error::UnsupportedTarget(other.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SurgeVersion {
    V2,
    #[default]
    V3,
    V4,
}

impl SurgeVersion {
    pub fn number(self) -> u8 {
        match self {
            Self::V2 => 2,
            Self::V3 => 3,
            Self::V4 => 4,
        }
    }
}

impl TryFrom<u8> for SurgeVersion {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            2 => Ok(Self::V2),
            3 => Ok(Self::V3),
            4 => Ok(Self::V4),
            _ => Err(Error::InvalidRequest(format!(
                "unsupported Surge version: {value}"
            ))),
        }
    }
}

impl FromStr for SurgeVersion {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        value
            .parse::<u8>()
            .map_err(|_| Error::InvalidRequest(format!("invalid Surge version: {value}")))
            .and_then(Self::try_from)
    }
}

impl fmt::Display for SurgeVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.number().fmt(formatter)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvertRequest {
    pub target: Target,
    pub sources: Vec<String>,
    pub config: Option<String>,
    pub user_agent: Option<String>,
    pub surge_version: Option<SurgeVersion>,
    pub options: ConvertOptions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeContext {
    pub unix_time_seconds: u64,
    pub random_seed: u64,
    pub scripts_authorized: bool,
}

impl RuntimeContext {
    pub fn system() -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        let unix_time_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        #[cfg(target_arch = "wasm32")]
        let unix_time_seconds = 0;
        Self {
            unix_time_seconds,
            #[cfg(not(target_arch = "wasm32"))]
            random_seed: unix_time_seconds ^ u64::from(std::process::id()),
            #[cfg(target_arch = "wasm32")]
            random_seed: 0,
            scripts_authorized: false,
        }
    }

    pub const fn deterministic(unix_time_seconds: u64, random_seed: u64) -> Self {
        Self {
            unix_time_seconds,
            random_seed,
            scripts_authorized: false,
        }
    }

    pub const fn with_scripts_authorized(mut self, authorized: bool) -> Self {
        self.scripts_authorized = authorized;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConvertOptions {
    pub include_remarks: Vec<String>,
    pub exclude_remarks: Vec<String>,
    pub node_group: Option<String>,
    pub rename_node: Vec<RegexMatchConfig>,
    pub emoji: Vec<RegexMatchConfig>,
    pub add_emoji: TriBool,
    pub remove_emoji: TriBool,
    pub append_proxy_type: TriBool,
    pub sort: TriBool,
    pub udp: TriBool,
    pub tcp_fast_open: TriBool,
    pub skip_cert_verify: TriBool,
    pub tls13: TriBool,
    pub nodelist: TriBool,
    pub filter_deprecated: TriBool,
    pub expand_rulesets: TriBool,
    pub classic_ruleset: TriBool,
}

pub fn convert_subscription(request: ConvertRequest) -> Result<String> {
    convert_subscription_with_context(request, RuntimeContext::system())
}

pub fn convert_subscription_with_context(
    request: ConvertRequest,
    context: RuntimeContext,
) -> Result<String> {
    let settings = request
        .config
        .as_deref()
        .map(Settings::detect_and_parse)
        .transpose()?;
    convert_subscription_with_settings(request, settings, context)
}

pub fn convert_subscription_with_settings(
    request: ConvertRequest,
    settings: Option<Settings>,
    context: RuntimeContext,
) -> Result<String> {
    let mut nodes = Vec::new();
    for source in &request.sources {
        nodes.extend(parse_subscription_source(source)?);
    }
    if nodes.is_empty() {
        return Err(Error::InvalidRequest("No nodes were found!".to_string()));
    }
    let mut options = request.options;
    let script_limits = settings.as_ref().map(|settings| {
        ScriptLimits::new(
            context.scripts_authorized,
            settings.script_memory_limit_bytes,
            settings.script_timeout_millis,
        )
    });
    if let Some(settings) = settings.as_ref() {
        ensure_scripts_allowed(settings, context.scripts_authorized)?;
        if settings.enable_filter && !settings.filter_script.is_empty() {
            filter_nodes_with_script(
                &mut nodes,
                &settings.filter_script,
                script_limits.as_ref().expect("settings are present"),
            )?;
        }
        apply_node_preferences(
            &mut nodes,
            settings,
            script_limits.as_ref().expect("settings are present"),
        )?;
        apply_settings_defaults_to_options(settings, &mut options);
    }
    let uses_script_sort = options.sort.get(false)
        && settings
            .as_ref()
            .is_some_and(|settings| !settings.sort_script.is_empty());
    apply_convert_options(
        &mut nodes,
        &options,
        script_limits.as_ref(),
        !uses_script_sort,
    )?;
    if uses_script_sort {
        let settings = settings.as_ref().expect("checked above");
        sort_nodes_with_script(
            &mut nodes,
            &settings.sort_script,
            script_limits.as_ref().expect("settings are present"),
        )?;
    }
    export_nodes(
        &nodes,
        request.target,
        request.surge_version.unwrap_or_default(),
        settings.as_ref(),
        &options,
    )
}

pub fn execute_subscription_script(
    script: &str,
    first_argument: &str,
    remaining_arguments: &[String],
    settings: &Settings,
    context: RuntimeContext,
) -> Result<String> {
    ensure_scripts_allowed_for_call(context.scripts_authorized)?;
    let limits = ScriptLimits::new(
        context.scripts_authorized,
        settings.script_memory_limit_bytes,
        settings.script_timeout_millis,
    );
    let value = quickjs_call(
        script,
        "parse",
        &[
            serde_json::Value::String(first_argument.to_string()),
            serde_json::Value::Array(
                remaining_arguments
                    .iter()
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        ],
        &limits,
    )?;
    value.as_str().map(ToOwned::to_owned).ok_or_else(|| {
        Error::InvalidRequest("subscription script parse() must return a string".to_string())
    })
}

pub fn execute_background_script(
    script: &str,
    settings: &Settings,
    timeout_millis: u64,
) -> Result<()> {
    let limits = ScriptLimits::new(true, settings.script_memory_limit_bytes, timeout_millis);
    let script = format!("{script}\nfunction __subconverter_background__() {{ return null; }}");
    quickjs_call(&script, "__subconverter_background__", &[], &limits).map(|_| ())
}

pub fn apply_settings_defaults_to_options(settings: &Settings, options: &mut ConvertOptions) {
    let append_proxy_type = if settings.append_proxy_type {
        TriBool::True
    } else {
        TriBool::False
    };
    let sort = if settings.sort_flag {
        TriBool::True
    } else {
        TriBool::False
    };
    options.append_proxy_type = options.append_proxy_type.or(append_proxy_type);
    options.sort = options.sort.or(sort);
    options.add_emoji = options.add_emoji.or(if settings.add_emoji {
        TriBool::True
    } else {
        TriBool::False
    });
    options.remove_emoji = options.remove_emoji.or(if settings.remove_old_emoji {
        TriBool::True
    } else {
        TriBool::False
    });
    if options.emoji.is_empty() {
        options.emoji = settings.emoji.clone();
    }
    options.udp = options.udp.or(settings.udp_flag);
    options.tcp_fast_open = options.tcp_fast_open.or(settings.tcp_fast_open_flag);
    options.skip_cert_verify = options.skip_cert_verify.or(settings.skip_cert_verify_flag);
    options.tls13 = options.tls13.or(settings.tls13_flag);
    options.filter_deprecated = options
        .filter_deprecated
        .or(if settings.filter_deprecated_nodes {
            TriBool::True
        } else {
            TriBool::False
        });
}

fn apply_convert_options(
    nodes: &mut Vec<Proxy>,
    options: &ConvertOptions,
    script_limits: Option<&ScriptLimits>,
    default_sort: bool,
) -> Result<()> {
    if !options.include_remarks.is_empty() {
        nodes.retain(|node| {
            options
                .include_remarks
                .iter()
                .any(|pattern| matcher_matches(pattern, node))
        });
    }
    if !options.exclude_remarks.is_empty() {
        nodes.retain(|node| {
            !options
                .exclude_remarks
                .iter()
                .any(|pattern| matcher_matches(pattern, node))
        });
    }
    for node in nodes.iter_mut() {
        if let Some(group) = options.node_group.as_ref() {
            node.group = group.clone();
        }
        if options.remove_emoji.get(false) {
            node.remark = remove_leading_emoji(&node.remark);
        }
        if !options.rename_node.is_empty() {
            apply_rename(node, &options.rename_node, script_limits)?;
        }
        if options.add_emoji.get(false) && !options.emoji.is_empty() {
            apply_emoji(node, &options.emoji, script_limits)?;
        }
        if options.append_proxy_type.get(false) {
            node.remark = format!("[{}] {}", proxy_type_label(node.proxy_type), node.remark);
        }
        node.udp = options.udp.or(node.udp);
        node.tcp_fast_open = options.tcp_fast_open.or(node.tcp_fast_open);
        node.allow_insecure = options.skip_cert_verify.or(node.allow_insecure);
        node.tls13 = options.tls13.or(node.tls13);
    }
    if options.sort.get(false) && default_sort {
        nodes.sort_by(|a, b| a.remark.cmp(&b.remark));
    }
    Ok(())
}

fn apply_node_preferences(
    nodes: &mut Vec<Proxy>,
    settings: &Settings,
    script_limits: &ScriptLimits,
) -> Result<()> {
    if !settings.include_remarks.is_empty() {
        nodes.retain(|node| {
            settings
                .include_remarks
                .iter()
                .any(|pattern| pattern_matches(pattern, &node.remark))
        });
    }
    if !settings.exclude_remarks.is_empty() {
        nodes.retain(|node| {
            !settings
                .exclude_remarks
                .iter()
                .any(|pattern| pattern_matches(pattern, &node.remark))
        });
    }
    for node in nodes.iter_mut() {
        apply_rename(node, &settings.rename_node, Some(script_limits))?;
    }
    Ok(())
}

fn apply_rename(
    node: &mut Proxy,
    rules: &[RegexMatchConfig],
    script_limits: Option<&ScriptLimits>,
) -> Result<()> {
    for rule in rules {
        if let Some(script) = rule.script.as_deref() {
            let limits = script_limits.ok_or_else(|| {
                Error::Forbidden("rename scripts require an authorized runtime".to_string())
            })?;
            if let Some(remark) = script_string(script, "rename", node, limits)? {
                if !remark.is_empty() {
                    node.remark = remark;
                }
            }
            continue;
        }
        if rule.r#match.is_empty() {
            continue;
        }
        if let Ok(regex) = Regex::new(&rule.r#match) {
            node.remark = regex
                .replace_all(&node.remark, rule.replace.as_str())
                .to_string();
        } else if node.remark.contains(&rule.r#match) {
            node.remark = node.remark.replace(&rule.r#match, &rule.replace);
        }
    }
    Ok(())
}

fn apply_emoji(
    node: &mut Proxy,
    rules: &[RegexMatchConfig],
    script_limits: Option<&ScriptLimits>,
) -> Result<()> {
    for rule in rules {
        if let Some(script) = rule.script.as_deref() {
            let limits = script_limits.ok_or_else(|| {
                Error::Forbidden("emoji scripts require an authorized runtime".to_string())
            })?;
            if let Some(emoji) = script_string(script, "getEmoji", node, limits)? {
                if !emoji.is_empty() {
                    node.remark = format!("{emoji} {}", node.remark);
                    return Ok(());
                }
            }
            continue;
        }
        if pattern_matches(&rule.r#match, &node.remark) && !node.remark.contains(&rule.replace) {
            node.remark = format!("{} {}", rule.replace, node.remark);
            return Ok(());
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(feature = "quickjs"), allow(dead_code))]
struct ScriptLimits {
    authorized: bool,
    memory_limit_bytes: usize,
    #[cfg(feature = "quickjs")]
    deadline: Instant,
}

impl ScriptLimits {
    fn new(authorized: bool, memory_limit_bytes: usize, timeout_millis: u64) -> Self {
        #[cfg(not(feature = "quickjs"))]
        let _ = timeout_millis;
        Self {
            authorized,
            memory_limit_bytes,
            #[cfg(feature = "quickjs")]
            deadline: Instant::now() + Duration::from_millis(timeout_millis.max(1)),
        }
    }
}

fn ensure_scripts_allowed(settings: &Settings, authorized: bool) -> Result<()> {
    let requested = (settings.enable_filter && !settings.filter_script.is_empty())
        || !settings.sort_script.is_empty()
        || settings
            .rename_node
            .iter()
            .chain(settings.emoji.iter())
            .chain(settings.stream_rule.iter())
            .chain(settings.time_rule.iter())
            .any(|rule| rule.script.is_some());
    if requested && !authorized {
        Err(Error::Forbidden(
            "scripts require an authorized request".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn ensure_scripts_allowed_for_call(authorized: bool) -> Result<()> {
    if authorized {
        Ok(())
    } else {
        Err(Error::Forbidden(
            "scripts require an authorized request".to_string(),
        ))
    }
}

fn filter_nodes_with_script(
    nodes: &mut Vec<Proxy>,
    script: &str,
    limits: &ScriptLimits,
) -> Result<()> {
    let mut filtered = Vec::with_capacity(nodes.len());
    for node in nodes.drain(..) {
        let keep = quickjs_call(script, "filter", &[proxy_script_value(&node)], limits)?
            .as_bool()
            .unwrap_or(false);
        if keep {
            filtered.push(node);
        }
    }
    *nodes = filtered;
    Ok(())
}

fn script_string(
    script: &str,
    function: &str,
    node: &Proxy,
    limits: &ScriptLimits,
) -> Result<Option<String>> {
    let value = quickjs_call(script, function, &[proxy_script_value(node)], limits)?;
    Ok(value.as_str().map(ToOwned::to_owned))
}

fn sort_nodes_with_script(nodes: &mut [Proxy], script: &str, limits: &ScriptLimits) -> Result<()> {
    let failure = std::cell::RefCell::new(None);
    nodes.sort_by(|left, right| {
        if failure.borrow().is_some() {
            return std::cmp::Ordering::Equal;
        }
        match quickjs_call(
            script,
            "compare",
            &[proxy_script_value(left), proxy_script_value(right)],
            limits,
        ) {
            Ok(serde_json::Value::Bool(true)) => std::cmp::Ordering::Less,
            Ok(serde_json::Value::Bool(false) | serde_json::Value::Null) => {
                std::cmp::Ordering::Equal
            }
            Ok(serde_json::Value::Number(number)) => match number.as_f64().unwrap_or(0.0) {
                number if number < 0.0 => std::cmp::Ordering::Less,
                number if number > 0.0 => std::cmp::Ordering::Greater,
                _ => std::cmp::Ordering::Equal,
            },
            Ok(_) => std::cmp::Ordering::Equal,
            Err(err) => {
                *failure.borrow_mut() = Some(err);
                std::cmp::Ordering::Equal
            }
        }
    });
    if let Some(err) = failure.into_inner() {
        Err(err)
    } else {
        Ok(())
    }
}

fn proxy_script_value(node: &Proxy) -> serde_json::Value {
    let mut info = serde_json::json!({
        "Type": proxy_type_label(node.proxy_type),
        "Id": node.id,
        "GroupId": node.group_id,
        "Group": node.group,
        "Remark": node.remark,
        "Server": node.hostname,
        "Hostname": node.hostname,
        "Port": node.port,
        "Username": node.username,
        "Password": node.password,
        "EncryptMethod": node.encrypt_method,
        "Plugin": node.plugin,
        "PluginOption": node.plugin_option,
        "Protocol": node.protocol,
        "ProtocolParam": node.protocol_param,
        "OBFS": node.obfs,
        "OBFSParam": node.obfs_param,
        "UserId": node.user_id,
        "AlterId": node.alter_id,
        "TransferProtocol": node.transfer_protocol,
        "FakeType": node.fake_type,
        "TLSSecure": node.tls_secure,
        "Host": node.host,
        "Path": node.path,
        "UDP": {"value": node.udp.get(false), "isDefined": !node.udp.is_undef()},
        "TCPFastOpen": {
            "value": node.tcp_fast_open.get(false),
            "isDefined": !node.tcp_fast_open.is_undef()
        },
        "AllowInsecure": {
            "value": node.allow_insecure.get(false),
            "isDefined": !node.allow_insecure.is_undef()
        },
        "TLS13": {"value": node.tls13.get(false), "isDefined": !node.tls13.is_undef()},
        "SnellVersion": node.snell_version,
        "ServerName": node.server_name,
        "SelfIP": node.self_ip,
        "SelfIPv6": node.self_ipv6,
        "PublicKey": node.public_key,
        "PrivateKey": node.private_key,
        "PreSharedKey": node.pre_shared_key,
        "DnsServers": node.dns_servers,
        "Mtu": node.mtu,
        "AllowedIPs": node.allowed_ips,
        "KeepAlive": node.keep_alive,
        "TestUrl": node.test_url,
        "ClientId": node.client_id,
    });
    let proxy_info = serde_json::to_string(&info).unwrap_or_else(|_| "{}".to_string());
    info.as_object_mut().expect("JSON object").insert(
        "ProxyInfo".to_string(),
        serde_json::Value::String(proxy_info),
    );
    info
}

#[cfg(feature = "quickjs")]
fn quickjs_call(
    script: &str,
    function: &str,
    arguments: &[serde_json::Value],
    limits: &ScriptLimits,
) -> Result<serde_json::Value> {
    if !limits.authorized {
        return Err(Error::Forbidden(
            "scripts require an authorized request".to_string(),
        ));
    }
    if script.starts_with("path:") {
        return Err(Error::InvalidRequest(
            "script path was not resolved by the platform adapter".to_string(),
        ));
    }
    if Instant::now() >= limits.deadline {
        return Err(Error::Timeout(
            "script execution deadline exceeded".to_string(),
        ));
    }
    let runtime = rquickjs::Runtime::new().map_err(|err| Error::InvalidRequest(err.to_string()))?;
    runtime.set_memory_limit(limits.memory_limit_bytes.max(64 * 1024));
    let deadline = limits.deadline;
    runtime.set_interrupt_handler(Some(Box::new(move || Instant::now() >= deadline)));
    let context =
        rquickjs::Context::full(&runtime).map_err(|err| Error::InvalidRequest(err.to_string()))?;
    let args = arguments
        .iter()
        .map(|argument| {
            let json = serde_json::to_string(argument).unwrap_or_else(|_| "null".to_string());
            format!(
                "JSON.parse({})",
                serde_json::to_string(&json).unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let source = format!(
        "{script}\n(function(){{const __result={function}({args});return JSON.stringify(__result === undefined ? null : __result);}})()"
    );
    let evaluated = context.with(|ctx| ctx.eval::<String, _>(source));
    match evaluated {
        Ok(json) => serde_json::from_str(&json)
            .map_err(|err| Error::InvalidRequest(format!("invalid script result: {err}"))),
        Err(_err) if Instant::now() >= limits.deadline => Err(Error::Timeout(
            "script execution deadline exceeded".to_string(),
        )),
        Err(err) => Err(Error::InvalidRequest(format!(
            "QuickJS execution failed: {err}"
        ))),
    }
}

#[cfg(not(feature = "quickjs"))]
fn quickjs_call(
    _script: &str,
    _function: &str,
    _arguments: &[serde_json::Value],
    _limits: &ScriptLimits,
) -> Result<serde_json::Value> {
    Err(Error::UnsupportedAdapterFeature(
        "QuickJS runtime".to_string(),
    ))
}

fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    Regex::new(pattern)
        .map(|regex| regex.is_match(value))
        .unwrap_or_else(|_| value.contains(pattern))
}

fn matcher_matches(pattern: &str, node: &Proxy) -> bool {
    let (matched, real_rule) = apply_matcher(pattern, node);
    matched && (real_rule.is_empty() || pattern_matches(&real_rule, &node.remark))
}

fn apply_matcher(rule: &str, node: &Proxy) -> (bool, String) {
    if let Some((target, real_rule)) = parse_prefixed_matcher(rule, "!!GROUP=") {
        return (pattern_matches(target, &node.group), real_rule.to_string());
    }
    if let Some((target, real_rule)) = parse_prefixed_matcher(rule, "!!TYPE=") {
        return (
            pattern_matches(target, proxy_type_label(node.proxy_type)),
            real_rule.to_string(),
        );
    }
    if let Some((target, real_rule)) = parse_prefixed_matcher(rule, "!!PORT=") {
        return (
            range_matches(target, node.port as i32),
            real_rule.to_string(),
        );
    }
    if let Some((target, real_rule)) = parse_prefixed_matcher(rule, "!!SERVER=") {
        return (
            pattern_matches(target, &node.hostname),
            real_rule.to_string(),
        );
    }
    if let Some((target, real_rule)) = parse_prefixed_matcher(rule, "!!GROUPID=") {
        return (
            range_matches(target, node.group_id as i32),
            real_rule.to_string(),
        );
    }
    (true, rule.to_string())
}

fn parse_prefixed_matcher<'a>(rule: &'a str, prefix: &str) -> Option<(&'a str, &'a str)> {
    let rest = rule.strip_prefix(prefix)?;
    if let Some((target, real_rule)) = rest.split_once("!!") {
        Some((target, real_rule))
    } else {
        Some((rest, ""))
    }
}

fn range_matches(range: &str, value: i32) -> bool {
    let mut matched = false;
    for item in range
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        if let Some(denied) = item.strip_prefix('!') {
            if range_item_matches(denied, value) {
                return false;
            }
            matched = true;
        } else if range_item_matches(item, value) {
            matched = true;
        }
    }
    matched
}

fn range_item_matches(item: &str, value: i32) -> bool {
    if let Some((start, end)) = item.split_once('-') {
        if start.is_empty() {
            return false;
        }
        let Ok(start) = start.parse::<i32>() else {
            return false;
        };
        if end.is_empty() {
            return value >= start;
        }
        return end
            .parse::<i32>()
            .map(|end| value >= start && value <= end)
            .unwrap_or(false);
    }
    if let Some(minimum) = item.strip_suffix('+') {
        return minimum
            .parse::<i32>()
            .map(|minimum| value >= minimum)
            .unwrap_or(false);
    }
    item.parse::<i32>()
        .map(|exact| value == exact)
        .unwrap_or(false)
}

fn remove_leading_emoji(value: &str) -> String {
    value
        .trim_start_matches(|ch: char| {
            matches!(
                ch,
                '\u{1F1E6}'..='\u{1F1FF}'
                    | '\u{1F300}'..='\u{1FAFF}'
                    | '\u{2600}'..='\u{27BF}'
            )
        })
        .trim_start()
        .to_string()
}

fn proxy_type_label(proxy_type: ProxyType) -> &'static str {
    match proxy_type {
        ProxyType::Shadowsocks => "SS",
        ProxyType::ShadowsocksR => "SSR",
        ProxyType::VMess => "VMESS",
        ProxyType::Trojan => "TROJAN",
        ProxyType::Snell => "SNELL",
        ProxyType::Http => "HTTP",
        ProxyType::Https => "HTTPS",
        ProxyType::Socks5 => "SOCKS5",
        ProxyType::WireGuard => "WIREGUARD",
        ProxyType::Hysteria => "HYSTERIA",
        ProxyType::Hysteria2 => "HYSTERIA2",
        ProxyType::Unknown => "UNKNOWN",
    }
}

pub fn parse_subscription_source(source: &str) -> Result<Vec<Proxy>> {
    if let Ok(nodes) = parse_clash_yaml(source) {
        if !nodes.is_empty() {
            return Ok(nodes);
        }
    }
    if let Ok(nodes) = parse_sip008_or_ssd_json(source) {
        if !nodes.is_empty() {
            return Ok(nodes);
        }
    }

    let mut nodes = Vec::new();
    for item in split_sources(source) {
        if item.starts_with("ss://") {
            nodes.push(parse_ss_link(&item)?);
        } else if item.starts_with("ssr://") {
            nodes.push(parse_ssr_link(&item)?);
        } else if item.starts_with("vmess://") {
            nodes.push(parse_vmess_link(&item)?);
        } else if item.starts_with("trojan://") {
            nodes.push(parse_trojan_link(&item)?);
        } else if item.starts_with("snell://") {
            nodes.push(parse_snell_link(&item)?);
        } else if item.starts_with("wireguard://") {
            nodes.push(parse_wireguard_link(&item)?);
        } else if item.starts_with("hysteria://") {
            nodes.push(parse_hysteria_link(&item)?);
        } else if item.starts_with("hysteria2://") || item.starts_with("hy2://") {
            nodes.push(parse_hysteria2_link(&item)?);
        } else if item.starts_with("tg://http")
            || item.starts_with("tg://socks")
            || item.starts_with("https://t.me/http")
            || item.starts_with("https://t.me/socks")
        {
            nodes.push(parse_telegram_proxy_link(&item)?);
        } else if item.starts_with("http://") || item.starts_with("https://") {
            nodes.push(parse_http_like_link(&item));
        } else if let Ok(decoded) = base64_decode(&item) {
            nodes.extend(parse_subscription_source(&decoded)?);
        }
    }
    Ok(nodes)
}

pub fn derive_subscription_userinfo(
    sources: &[String],
    settings: Option<&Settings>,
) -> Option<String> {
    derive_subscription_userinfo_with_context(sources, settings, RuntimeContext::system())
}

pub fn derive_subscription_userinfo_with_context(
    sources: &[String],
    settings: Option<&Settings>,
    context: RuntimeContext,
) -> Option<String> {
    let settings = settings?;
    if settings.stream_rule.is_empty() && settings.time_rule.is_empty() {
        return None;
    }
    let mut nodes = Vec::new();
    for source in sources {
        if let Ok(mut parsed) = parse_subscription_source(source) {
            nodes.append(&mut parsed);
        }
    }
    if nodes.is_empty() {
        return None;
    }
    derive_subscription_userinfo_from_nodes(
        &nodes,
        &settings.stream_rule,
        &settings.time_rule,
        context.unix_time_seconds,
    )
}

fn derive_subscription_userinfo_from_nodes(
    nodes: &[Proxy],
    stream_rules: &[RegexMatchConfig],
    time_rules: &[RegexMatchConfig],
    now_unix_seconds: u64,
) -> Option<String> {
    let stream_info = first_replaced_remark(nodes, stream_rules);
    let time_info = first_replaced_remark(nodes, time_rules);
    if stream_info.is_none() && time_info.is_none() {
        return None;
    }

    let mut total = 0;
    let mut used = 0;
    if let Some(stream_info) = stream_info.as_deref() {
        let args = url::form_urlencoded::parse(stream_info.as_bytes())
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<std::collections::BTreeMap<_, _>>();
        let total_str = args.get("total").map(String::as_str).unwrap_or("");
        let left_str = args.get("left").map(String::as_str).unwrap_or("");
        let used_str = args.get("used").map(String::as_str).unwrap_or("");
        if total_str.contains('%') {
            let percent = percent_to_float(total_str);
            if !used_str.is_empty() && percent < 1.0 {
                used = stream_to_int(used_str);
                total = (used as f64 / (1.0 - percent)) as u64;
            } else if !left_str.is_empty() && percent > 0.0 {
                let left = stream_to_int(left_str);
                total = (left as f64 / percent) as u64;
                used = total.saturating_sub(left.min(total));
            }
        } else {
            total = stream_to_int(total_str);
            if !used_str.is_empty() {
                used = stream_to_int(used_str);
            } else if !left_str.is_empty() {
                let left = stream_to_int(left_str);
                used = total.saturating_sub(left.min(total));
            }
        }
    }

    let mut result = format!("upload=0; download={used}; total={total};");
    if let Some(expire) = time_info
        .as_deref()
        .and_then(|value| expire_to_timestamp(value, now_unix_seconds))
    {
        result.push_str(&format!(" expire={expire};"));
    }
    Some(result)
}

fn first_replaced_remark(nodes: &[Proxy], rules: &[RegexMatchConfig]) -> Option<String> {
    for node in nodes {
        for rule in rules.iter().filter(|rule| rule.script.is_none()) {
            let Ok(regex) = Regex::new(&rule.r#match) else {
                continue;
            };
            if regex.is_match(&node.remark) {
                let replaced = regex
                    .replace(&node.remark, rule.replace.as_str())
                    .to_string();
                if replaced != node.remark {
                    return Some(replaced);
                }
            }
        }
    }
    None
}

fn stream_to_int(value: &str) -> u64 {
    let value = value.trim();
    if value.is_empty() {
        return 0;
    }
    let units = [
        ("EB", 6_u32),
        ("PB", 5),
        ("TB", 4),
        ("GB", 3),
        ("MB", 2),
        ("KB", 1),
        ("B", 0),
    ];
    for (suffix, power) in units {
        if let Some(number) = value.strip_suffix(suffix) {
            let number = number.trim().parse::<f64>().unwrap_or(0.0);
            return (number * 1024_f64.powi(power as i32)) as u64;
        }
    }
    value.parse::<u64>().unwrap_or(0)
}

fn percent_to_float(value: &str) -> f64 {
    value
        .trim()
        .strip_suffix('%')
        .and_then(|number| number.parse::<f64>().ok())
        .map(|number| number / 100.0)
        .unwrap_or(0.0)
}

fn expire_to_timestamp(value: &str, now_unix_seconds: u64) -> Option<u64> {
    let value = value.trim();
    if let Some(days) = value
        .strip_prefix("left=")
        .and_then(|value| value.strip_suffix('d'))
    {
        let seconds = (days.parse::<f64>().ok()? * 86400.0) as u64;
        return Some(now_unix_seconds.saturating_add(seconds));
    }
    None
}

fn parse_clash_yaml(source: &str) -> Result<Vec<Proxy>> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(source).map_err(|err| Error::Parse(err.to_string()))?;
    let proxies = value
        .get("proxies")
        .and_then(serde_yaml::Value::as_sequence)
        .ok_or_else(|| Error::Parse("clash yaml has no proxies array".to_string()))?;
    let mut nodes = Vec::new();
    for proxy in proxies {
        let proxy_type = yaml_str(proxy, "type")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let mut node = Proxy {
            remark: yaml_str(proxy, "name").unwrap_or_default(),
            hostname: yaml_str(proxy, "server").unwrap_or_default(),
            port: yaml_u16(proxy, "port").unwrap_or_default(),
            ..Proxy::default()
        };
        match proxy_type.as_str() {
            "ss" => {
                node.proxy_type = ProxyType::Shadowsocks;
                node.group = "SSProvider".to_string();
                node.encrypt_method = yaml_str(proxy, "cipher").unwrap_or_default();
                node.password = yaml_str(proxy, "password").unwrap_or_default();
                node.plugin = yaml_str(proxy, "plugin").unwrap_or_default();
                node.plugin_option = yaml_str(proxy, "plugin-opts")
                    .or_else(|| yaml_str(proxy, "plugin-opts.mode"))
                    .unwrap_or_default();
            }
            "ssr" => {
                node.proxy_type = ProxyType::ShadowsocksR;
                node.group = "SSRProvider".to_string();
                node.encrypt_method =
                    yaml_str(proxy, "cipher").unwrap_or_else(|| "auto".to_string());
                node.password = yaml_str(proxy, "password").unwrap_or_default();
                node.protocol = yaml_str(proxy, "protocol").unwrap_or_default();
                node.protocol_param = yaml_str(proxy, "protocol-param").unwrap_or_default();
                node.obfs = yaml_str(proxy, "obfs").unwrap_or_default();
                node.obfs_param = yaml_str(proxy, "obfs-param").unwrap_or_default();
            }
            "vmess" => {
                node.proxy_type = ProxyType::VMess;
                node.group = "V2RayProvider".to_string();
                node.user_id = yaml_str(proxy, "uuid").unwrap_or_default();
                node.alter_id = yaml_u16(proxy, "alterId")
                    .or_else(|| yaml_u16(proxy, "alter-id"))
                    .unwrap_or_default();
                node.encrypt_method =
                    yaml_str(proxy, "cipher").unwrap_or_else(|| "auto".to_string());
                node.transfer_protocol =
                    yaml_str(proxy, "network").unwrap_or_else(|| "tcp".to_string());
                node.tls_secure = yaml_bool(proxy, "tls").unwrap_or(false);
                node.server_name = yaml_str(proxy, "servername")
                    .or_else(|| yaml_str(proxy, "sni"))
                    .unwrap_or_default();
                node.host = yaml_str(proxy, "ws-opts.headers.Host")
                    .or_else(|| yaml_str(proxy, "ws-opts.host"))
                    .or_else(|| yaml_string_list(proxy, "h2-opts.host").into_iter().next())
                    .unwrap_or_default();
                node.path = yaml_str(proxy, "ws-opts.path")
                    .or_else(|| yaml_str(proxy, "h2-opts.path"))
                    .or_else(|| yaml_str(proxy, "grpc-opts.grpc-service-name"))
                    .or_else(|| yaml_str(proxy, "path"))
                    .unwrap_or_default();
            }
            "trojan" => {
                node.proxy_type = ProxyType::Trojan;
                node.group = "TrojanProvider".to_string();
                node.password = yaml_str(proxy, "password").unwrap_or_default();
                node.sni = yaml_str(proxy, "sni").unwrap_or_default();
                node.transfer_protocol =
                    yaml_str(proxy, "network").unwrap_or_else(|| "tcp".to_string());
                node.host = yaml_str(proxy, "ws-opts.headers.Host")
                    .or_else(|| yaml_str(proxy, "ws-opts.host"))
                    .unwrap_or_default();
                node.path = yaml_str(proxy, "ws-opts.path")
                    .or_else(|| yaml_str(proxy, "grpc-opts.grpc-service-name"))
                    .or_else(|| yaml_str(proxy, "path"))
                    .unwrap_or_default();
                node.tls_secure = true;
            }
            "snell" => {
                node.proxy_type = ProxyType::Snell;
                node.group = "SnellProvider".to_string();
                node.password = yaml_str(proxy, "psk")
                    .or_else(|| yaml_str(proxy, "password"))
                    .unwrap_or_default();
                node.obfs = yaml_str(proxy, "obfs-opts.mode")
                    .or_else(|| yaml_str(proxy, "obfs"))
                    .unwrap_or_default();
                node.host = yaml_str(proxy, "obfs-opts.host")
                    .or_else(|| yaml_str(proxy, "obfs-host"))
                    .unwrap_or_default();
                node.snell_version = yaml_u16(proxy, "version").unwrap_or_default();
                node.tcp_fast_open = yaml_bool(proxy, "tfo")
                    .or_else(|| yaml_bool(proxy, "fast-open"))
                    .map(|value| if value { TriBool::True } else { TriBool::False })
                    .unwrap_or_default();
            }
            "socks5" | "socks" => {
                node.proxy_type = ProxyType::Socks5;
                node.group = "SocksProvider".to_string();
                node.username = yaml_str(proxy, "username").unwrap_or_default();
                node.password = yaml_str(proxy, "password").unwrap_or_default();
            }
            "http" => {
                node.proxy_type = ProxyType::Http;
                node.group = "HTTPProvider".to_string();
                node.username = yaml_str(proxy, "username").unwrap_or_default();
                node.password = yaml_str(proxy, "password").unwrap_or_default();
            }
            "wireguard" => {
                node.proxy_type = ProxyType::WireGuard;
                node.group = "WireGuardProvider".to_string();
                node.self_ip = yaml_str(proxy, "ip")
                    .or_else(|| yaml_str(proxy, "self-ip"))
                    .unwrap_or_default();
                node.self_ipv6 = yaml_str(proxy, "ipv6")
                    .or_else(|| yaml_str(proxy, "self-ipv6"))
                    .unwrap_or_default();
                node.private_key = yaml_str(proxy, "private-key").unwrap_or_default();
                node.public_key = yaml_str(proxy, "public-key").unwrap_or_default();
                node.pre_shared_key = yaml_str(proxy, "preshared-key")
                    .or_else(|| yaml_str(proxy, "pre-shared-key"))
                    .unwrap_or_default();
                node.dns_servers = yaml_string_list(proxy, "dns");
                node.mtu = yaml_u16(proxy, "mtu").unwrap_or_default();
                node.keep_alive = yaml_u16(proxy, "keepalive").unwrap_or_default();
                node.allowed_ips =
                    yaml_str(proxy, "allowed-ips").unwrap_or_else(|| "0.0.0.0/0, ::/0".to_string());
                node.udp = crate::model::TriBool::True;
            }
            "hysteria" => {
                node.proxy_type = ProxyType::Hysteria;
                node.group = "HysteriaProvider".to_string();
                node.protocol = yaml_str(proxy, "protocol").unwrap_or_default();
                node.obfs = yaml_str(proxy, "obfs").unwrap_or_default();
                node.obfs_param = yaml_str(proxy, "obfs-protocol").unwrap_or_default();
                node.auth_str = yaml_str(proxy, "auth-str")
                    .or_else(|| yaml_str(proxy, "auth"))
                    .unwrap_or_default();
                node.sni = yaml_str(proxy, "sni").unwrap_or_default();
                node.fingerprint = yaml_str(proxy, "fingerprint").unwrap_or_default();
                node.alpn = yaml_string_list(proxy, "alpn");
                node.up = yaml_str(proxy, "up").unwrap_or_default();
                node.down = yaml_str(proxy, "down").unwrap_or_default();
                node.up_speed = yaml_u32(proxy, "up-speed").unwrap_or_default();
                node.down_speed = yaml_u32(proxy, "down-speed").unwrap_or_default();
                node.allow_insecure = yaml_bool(proxy, "skip-cert-verify")
                    .map(|value| {
                        if value {
                            crate::model::TriBool::True
                        } else {
                            crate::model::TriBool::False
                        }
                    })
                    .unwrap_or_default();
            }
            "hysteria2" | "hy2" => {
                node.proxy_type = ProxyType::Hysteria2;
                node.group = "Hysteria2Provider".to_string();
                node.password = yaml_str(proxy, "password").unwrap_or_default();
                node.obfs = yaml_str(proxy, "obfs").unwrap_or_default();
                node.obfs_param = yaml_str(proxy, "obfs-password")
                    .or_else(|| yaml_str(proxy, "obfs-param"))
                    .unwrap_or_default();
                node.sni = yaml_str(proxy, "sni").unwrap_or_default();
                node.fingerprint = yaml_str(proxy, "fingerprint").unwrap_or_default();
                node.alpn = yaml_string_list(proxy, "alpn");
                node.up = yaml_str(proxy, "up").unwrap_or_default();
                node.down = yaml_str(proxy, "down").unwrap_or_default();
                node.allow_insecure = yaml_bool(proxy, "skip-cert-verify")
                    .map(|value| {
                        if value {
                            crate::model::TriBool::True
                        } else {
                            crate::model::TriBool::False
                        }
                    })
                    .unwrap_or_default();
            }
            _ => continue,
        }
        nodes.push(node);
    }
    Ok(nodes)
}

fn parse_sip008_or_ssd_json(source: &str) -> Result<Vec<Proxy>> {
    let value: serde_json::Value =
        serde_json::from_str(source).map_err(|err| Error::Parse(err.to_string()))?;
    let servers = value
        .get("servers")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| Error::Parse("json has no servers array".to_string()))?;
    let default_method = json_string(&value, "encryption").unwrap_or_default();
    let default_password = json_string(&value, "password").unwrap_or_default();
    let mut nodes = Vec::new();
    for server in servers {
        let hostname = json_string(server, "server")
            .or_else(|| json_string(server, "host"))
            .unwrap_or_default();
        let port = json_string(server, "port")
            .and_then(|value| value.parse().ok())
            .or_else(|| {
                server
                    .get("port")
                    .and_then(serde_json::Value::as_u64)
                    .map(|value| value as u16)
            })
            .unwrap_or_default();
        let method = json_string(server, "encryption")
            .or_else(|| json_string(server, "method"))
            .unwrap_or_else(|| default_method.clone());
        let password = json_string(server, "password").unwrap_or_else(|| default_password.clone());
        let remark = json_string(server, "remarks")
            .or_else(|| json_string(server, "name"))
            .unwrap_or_else(|| hostname.clone());
        nodes.push(Proxy {
            proxy_type: ProxyType::Shadowsocks,
            group: "SSProvider".to_string(),
            remark,
            hostname,
            port,
            encrypt_method: method,
            password,
            plugin: json_string(server, "plugin").unwrap_or_default(),
            plugin_option: json_string(server, "plugin_options")
                .or_else(|| json_string(server, "plugin-opts"))
                .unwrap_or_default(),
            ..Proxy::default()
        });
    }
    Ok(nodes)
}

fn parse_ss_link(link: &str) -> Result<Proxy> {
    let body = link.trim_start_matches("ss://");
    let (payload, fragment) = split_fragment(body);
    let decoded = if payload.contains('@') {
        payload.to_string()
    } else {
        base64_decode(payload)?
    };
    let (userinfo, hostport) = decoded
        .split_once('@')
        .ok_or_else(|| Error::Parse("invalid ss link: missing @".to_string()))?;
    let decoded_userinfo = if userinfo.contains(':') {
        userinfo.to_string()
    } else {
        base64_decode(userinfo)?
    };
    let (method, password) = decoded_userinfo
        .split_once(':')
        .ok_or_else(|| Error::Parse("invalid ss link: missing method/password".to_string()))?;
    let (hostname, port) = split_host_port(hostport)?;
    Ok(Proxy {
        proxy_type: ProxyType::Shadowsocks,
        group: "SSProvider".to_string(),
        remark: fragment.unwrap_or_else(|| hostname.clone()),
        hostname,
        port,
        encrypt_method: method.to_string(),
        password: password.to_string(),
        ..Proxy::default()
    })
}

fn parse_ssr_link(link: &str) -> Result<Proxy> {
    let decoded = base64_decode(link.trim_start_matches("ssr://"))?;
    let (main, query) = decoded.split_once("/?").unwrap_or((&decoded, ""));
    let parts = main.split(':').collect::<Vec<_>>();
    if parts.len() < 6 {
        return Err(Error::Parse(
            "invalid ssr link: expected 6 fields".to_string(),
        ));
    }
    let query_args = url::form_urlencoded::parse(query.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let remark = query_args
        .get("remarks")
        .and_then(|value| base64_decode(value).ok())
        .unwrap_or_else(|| parts[0].to_string());
    let group = query_args
        .get("group")
        .and_then(|value| base64_decode(value).ok())
        .unwrap_or_else(|| "SSRProvider".to_string());
    Ok(Proxy {
        proxy_type: ProxyType::ShadowsocksR,
        group,
        remark,
        hostname: parts[0].to_string(),
        port: parts[1].parse().unwrap_or_default(),
        protocol: parts[2].to_string(),
        encrypt_method: parts[3].to_string(),
        obfs: parts[4].to_string(),
        password: base64_decode(parts[5]).unwrap_or_else(|_| parts[5].to_string()),
        obfs_param: query_args
            .get("obfsparam")
            .and_then(|value| base64_decode(value).ok())
            .unwrap_or_default(),
        protocol_param: query_args
            .get("protoparam")
            .and_then(|value| base64_decode(value).ok())
            .unwrap_or_default(),
        ..Proxy::default()
    })
}

fn parse_vmess_link(link: &str) -> Result<Proxy> {
    let body = link.trim_start_matches("vmess://");
    let decoded = base64_decode(body)?;
    let value: serde_json::Value = serde_json::from_str(&decoded)
        .map_err(|err| Error::Parse(format!("invalid vmess json: {err}")))?;
    Ok(Proxy {
        proxy_type: ProxyType::VMess,
        group: "V2RayProvider".to_string(),
        remark: json_string(&value, "ps").unwrap_or_else(|| "VMess".to_string()),
        hostname: json_string(&value, "add").unwrap_or_default(),
        port: json_string(&value, "port")
            .and_then(|p| p.parse().ok())
            .unwrap_or_default(),
        user_id: json_string(&value, "id").unwrap_or_default(),
        alter_id: json_string(&value, "aid")
            .and_then(|p| p.parse().ok())
            .unwrap_or_default(),
        transfer_protocol: json_string(&value, "net").unwrap_or_else(|| "tcp".to_string()),
        encrypt_method: json_string(&value, "scy").unwrap_or_default(),
        path: json_string(&value, "path").unwrap_or_default(),
        host: json_string(&value, "host").unwrap_or_default(),
        server_name: json_string(&value, "sni").unwrap_or_default(),
        tls_secure: json_string(&value, "tls").as_deref() == Some("tls"),
        ..Proxy::default()
    })
}

fn parse_trojan_link(link: &str) -> Result<Proxy> {
    let url =
        url::Url::parse(link).map_err(|err| Error::Parse(format!("invalid trojan url: {err}")))?;
    let query = query_pairs(&url);
    Ok(Proxy {
        proxy_type: ProxyType::Trojan,
        group: "TrojanProvider".to_string(),
        remark: crate::util::url_decode(
            url.fragment().unwrap_or(url.host_str().unwrap_or("Trojan")),
        ),
        hostname: url.host_str().unwrap_or_default().to_string(),
        port: url.port().unwrap_or(443),
        password: crate::util::url_decode(url.username()),
        tls_secure: true,
        transfer_protocol: first_query(&query, &["type", "network"])
            .unwrap_or_else(|| "tcp".to_string()),
        path: first_query(&query, &["path", "serviceName", "service-name"]).unwrap_or_default(),
        host: first_query(&query, &["host", "ws-host"]).unwrap_or_default(),
        sni: first_query(&query, &["sni", "peer"]).unwrap_or_default(),
        allow_insecure: query_bool(&query, "skip-cert-verify"),
        ..Proxy::default()
    })
}

fn parse_snell_link(link: &str) -> Result<Proxy> {
    let url =
        url::Url::parse(link).map_err(|err| Error::Parse(format!("invalid snell url: {err}")))?;
    let query = query_pairs(&url);
    let hostname = url.host_str().unwrap_or_default().to_string();
    Ok(Proxy {
        proxy_type: ProxyType::Snell,
        group: "SnellProvider".to_string(),
        remark: url.fragment().unwrap_or(&hostname).to_string(),
        hostname,
        port: url.port().unwrap_or(0),
        password: first_query(&query, &["psk", "password"])
            .unwrap_or_else(|| url.username().to_string()),
        obfs: first_query(&query, &["obfs", "obfs-mode"]).unwrap_or_default(),
        host: first_query(&query, &["obfs-host", "host"]).unwrap_or_default(),
        snell_version: query_u16(&query, "version").unwrap_or_default(),
        tcp_fast_open: query_bool(&query, "tfo"),
        allow_insecure: query_bool(&query, "skip-cert-verify"),
        ..Proxy::default()
    })
}

fn parse_wireguard_link(link: &str) -> Result<Proxy> {
    let url = url::Url::parse(link)
        .map_err(|err| Error::Parse(format!("invalid wireguard url: {err}")))?;
    let query = query_pairs(&url);
    let hostname = url.host_str().unwrap_or_default().to_string();
    Ok(Proxy {
        proxy_type: ProxyType::WireGuard,
        group: "WireGuardProvider".to_string(),
        remark: url.fragment().unwrap_or(&hostname).to_string(),
        hostname,
        port: url.port().unwrap_or(0),
        public_key: first_query(&query, &["public-key", "public_key"])
            .unwrap_or_else(|| url.username().to_string()),
        private_key: first_query(&query, &["private-key", "private_key"]).unwrap_or_default(),
        pre_shared_key: first_query(&query, &["pre-shared-key", "preshared-key", "psk"])
            .unwrap_or_default(),
        self_ip: first_query(&query, &["ip", "self-ip", "self_ip"]).unwrap_or_default(),
        self_ipv6: first_query(&query, &["ipv6", "self-ipv6", "self_ipv6"]).unwrap_or_default(),
        dns_servers: query_list(&query, "dns"),
        mtu: query_u16(&query, "mtu").unwrap_or_default(),
        keep_alive: first_query(&query, &["keepalive", "keep-alive", "persistent-keepalive"])
            .and_then(|value| value.parse().ok())
            .unwrap_or_default(),
        allowed_ips: first_query(&query, &["allowed-ips", "allowed_ips"])
            .unwrap_or_else(|| "0.0.0.0/0, ::/0".to_string()),
        udp: TriBool::True,
        ..Proxy::default()
    })
}

fn parse_hysteria_link(link: &str) -> Result<Proxy> {
    let url = url::Url::parse(link)
        .map_err(|err| Error::Parse(format!("invalid hysteria url: {err}")))?;
    let query = query_pairs(&url);
    let hostname = url.host_str().unwrap_or_default().to_string();
    Ok(Proxy {
        proxy_type: ProxyType::Hysteria,
        group: "HysteriaProvider".to_string(),
        remark: url.fragment().unwrap_or(&hostname).to_string(),
        hostname,
        port: url.port().unwrap_or(0),
        protocol: first_query(&query, &["protocol"]).unwrap_or_default(),
        obfs: first_query(&query, &["obfs"]).unwrap_or_default(),
        obfs_param: first_query(&query, &["obfs-protocol", "obfs_param"]).unwrap_or_default(),
        auth_str: first_query(&query, &["auth-str", "auth_str", "auth"])
            .unwrap_or_else(|| url.username().to_string()),
        sni: first_query(&query, &["sni", "peer"]).unwrap_or_default(),
        fingerprint: first_query(&query, &["fingerprint"]).unwrap_or_default(),
        alpn: query_list(&query, "alpn"),
        up: first_query(&query, &["up"]).unwrap_or_default(),
        down: first_query(&query, &["down"]).unwrap_or_default(),
        up_speed: query_u32(&query, "up-speed").unwrap_or_default(),
        down_speed: query_u32(&query, "down-speed").unwrap_or_default(),
        allow_insecure: query_bool(&query, "skip-cert-verify"),
        ..Proxy::default()
    })
}

fn parse_hysteria2_link(link: &str) -> Result<Proxy> {
    let url = url::Url::parse(link)
        .map_err(|err| Error::Parse(format!("invalid hysteria2 url: {err}")))?;
    let query = query_pairs(&url);
    let hostname = url.host_str().unwrap_or_default().to_string();
    Ok(Proxy {
        proxy_type: ProxyType::Hysteria2,
        group: "Hysteria2Provider".to_string(),
        remark: url.fragment().unwrap_or(&hostname).to_string(),
        hostname,
        port: url.port().unwrap_or(0),
        password: first_query(&query, &["password"]).unwrap_or_else(|| url.username().to_string()),
        obfs: first_query(&query, &["obfs"]).unwrap_or_default(),
        obfs_param: first_query(&query, &["obfs-password", "obfs_param", "obfs-param"])
            .unwrap_or_default(),
        sni: first_query(&query, &["sni", "peer"]).unwrap_or_default(),
        fingerprint: first_query(&query, &["fingerprint"]).unwrap_or_default(),
        alpn: query_list(&query, "alpn"),
        up: first_query(&query, &["up"]).unwrap_or_default(),
        down: first_query(&query, &["down"]).unwrap_or_default(),
        allow_insecure: query_bool(&query, "skip-cert-verify"),
        ..Proxy::default()
    })
}

fn parse_http_like_link(link: &str) -> Proxy {
    let parsed = url::Url::parse(link).ok();
    let is_https = link.starts_with("https://");
    Proxy {
        proxy_type: if is_https {
            ProxyType::Https
        } else {
            ProxyType::Http
        },
        group: "HTTPProvider".to_string(),
        remark: parsed
            .as_ref()
            .and_then(|url| url.fragment().or_else(|| url.host_str()))
            .unwrap_or("HTTP")
            .to_string(),
        username: parsed
            .as_ref()
            .map(|url| url.username().to_string())
            .unwrap_or_default(),
        password: parsed
            .as_ref()
            .and_then(url::Url::password)
            .unwrap_or_default()
            .to_string(),
        hostname: parsed
            .as_ref()
            .and_then(url::Url::host_str)
            .unwrap_or_default()
            .to_string(),
        port: parsed
            .as_ref()
            .and_then(url::Url::port)
            .unwrap_or(if is_https { 443 } else { 80 }),
        tls_secure: is_https,
        ..Proxy::default()
    }
}

fn parse_telegram_proxy_link(link: &str) -> Result<Proxy> {
    let normalized = link
        .replace("https://t.me/http?", "tg://http?")
        .replace("https://t.me/socks?", "tg://socks?");
    let url = url::Url::parse(&normalized)
        .map_err(|err| Error::Parse(format!("invalid telegram proxy url: {err}")))?;
    let args = url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    let server = args
        .get("server")
        .ok_or(Error::MissingArgument("server"))?
        .to_string();
    let port = args
        .get("port")
        .and_then(|value| value.parse().ok())
        .unwrap_or_default();
    let username = args
        .get("user")
        .map(ToString::to_string)
        .unwrap_or_default();
    let password = args
        .get("pass")
        .map(ToString::to_string)
        .unwrap_or_default();
    let remark = format!("{server}:{port}");
    Ok(Proxy {
        proxy_type: if normalized.starts_with("tg://socks") {
            ProxyType::Socks5
        } else {
            ProxyType::Http
        },
        group: if normalized.starts_with("tg://socks") {
            "SocksProvider".to_string()
        } else {
            "HTTPProvider".to_string()
        },
        remark,
        hostname: server,
        port,
        username,
        password,
        ..Proxy::default()
    })
}

fn export_nodes(
    nodes: &[Proxy],
    target: Target,
    surge_version: SurgeVersion,
    settings: Option<&Settings>,
    options: &ConvertOptions,
) -> Result<String> {
    let mut compatible = nodes
        .iter()
        .filter(|node| target_supports_proxy(target, node.proxy_type))
        .cloned()
        .collect::<Vec<_>>();
    make_unique_remarks(&mut compatible);
    let nodes = compatible.as_slice();
    match target {
        Target::Clash | Target::ClashR => {
            export_clash(nodes, target == Target::ClashR, settings, options)
        }
        Target::SingBox => export_singbox(nodes, settings, options),
        Target::Shadowsocks => Ok(export_single_links(nodes, ProxyType::Shadowsocks)),
        Target::ShadowsocksSub => export_sssub(nodes, settings, options),
        Target::ShadowsocksR => Ok(export_single_links(nodes, ProxyType::ShadowsocksR)),
        Target::V2Ray => Ok(base64_encode(&export_v2ray_links(nodes).join("\n"))),
        Target::Trojan => Ok(export_trojan_links(nodes)),
        Target::Surge => Ok(apply_text_rule_base(
            export_surge(nodes, surge_version, !options.nodelist.get(false)),
            target,
            settings,
            options,
        )),
        Target::Mellow => Ok(apply_text_rule_base(
            export_mellow(nodes),
            target,
            settings,
            options,
        )),
        Target::Quan => Ok(apply_text_rule_base(
            export_quan(nodes, settings),
            target,
            settings,
            options,
        )),
        Target::QuanX => Ok(apply_text_rule_base(
            export_quanx(nodes, settings),
            target,
            settings,
            options,
        )),
        Target::Loon => Ok(apply_text_rule_base(
            export_loon(nodes),
            target,
            settings,
            options,
        )),
        Target::Surfboard => Ok(apply_text_rule_base(
            export_surfboard(nodes, !options.nodelist.get(false)),
            target,
            settings,
            options,
        )),
        Target::Mixed => Ok(export_mixed(nodes)),
        Target::Ssd => export_ssd(nodes),
    }
}

fn make_unique_remarks(nodes: &mut [Proxy]) {
    let mut used = Vec::<String>::with_capacity(nodes.len());
    for node in nodes {
        node.remark = node.remark.replace('=', "-");
        let base = node.remark.clone();
        let mut candidate = base.clone();
        let mut suffix = 2;
        while used.iter().any(|remark| remark == &candidate) {
            candidate = format!("{base} {suffix}");
            suffix += 1;
        }
        node.remark = candidate.clone();
        used.push(candidate);
    }
}

fn target_supports_proxy(target: Target, proxy_type: ProxyType) -> bool {
    match target {
        Target::Clash | Target::ClashR => !matches!(proxy_type, ProxyType::Unknown),
        Target::SingBox => matches!(
            proxy_type,
            ProxyType::Shadowsocks
                | ProxyType::ShadowsocksR
                | ProxyType::VMess
                | ProxyType::Trojan
                | ProxyType::Snell
                | ProxyType::Socks5
                | ProxyType::Http
                | ProxyType::Https
                | ProxyType::WireGuard
                | ProxyType::Hysteria
                | ProxyType::Hysteria2
        ),
        Target::Shadowsocks | Target::ShadowsocksSub | Target::Ssd => {
            proxy_type == ProxyType::Shadowsocks
        }
        Target::ShadowsocksR => proxy_type == ProxyType::ShadowsocksR,
        Target::V2Ray => proxy_type == ProxyType::VMess,
        Target::Trojan => proxy_type == ProxyType::Trojan,
        Target::Mixed => matches!(
            proxy_type,
            ProxyType::Shadowsocks | ProxyType::ShadowsocksR | ProxyType::VMess | ProxyType::Trojan
        ),
        Target::Surge => matches!(
            proxy_type,
            ProxyType::Shadowsocks
                | ProxyType::VMess
                | ProxyType::Trojan
                | ProxyType::Snell
                | ProxyType::Socks5
                | ProxyType::Http
                | ProxyType::Https
        ),
        Target::Surfboard => matches!(
            proxy_type,
            ProxyType::Shadowsocks
                | ProxyType::VMess
                | ProxyType::Trojan
                | ProxyType::Socks5
                | ProxyType::Http
                | ProxyType::Https
        ),
        Target::Quan | Target::QuanX | Target::Loon => matches!(
            proxy_type,
            ProxyType::Shadowsocks
                | ProxyType::VMess
                | ProxyType::Trojan
                | ProxyType::Socks5
                | ProxyType::Http
                | ProxyType::Https
        ),
        Target::Mellow => matches!(
            proxy_type,
            ProxyType::Shadowsocks | ProxyType::VMess | ProxyType::Trojan
        ),
    }
}

fn export_clash(
    nodes: &[Proxy],
    clash_r: bool,
    settings: Option<&Settings>,
    options: &ConvertOptions,
) -> Result<String> {
    let export_nodes = nodes
        .iter()
        .filter(|node| !is_deprecated_for_clash(node, clash_r, options))
        .collect::<Vec<_>>();
    let mut proxies = Vec::new();
    for node in &export_nodes {
        let mut entry = serde_json::Map::new();
        entry.insert(
            "name".to_string(),
            serde_json::Value::String(node.remark.clone()),
        );
        entry.insert(
            "server".to_string(),
            serde_json::Value::String(node.hostname.clone()),
        );
        entry.insert(
            "port".to_string(),
            serde_json::Value::Number(node.port.into()),
        );
        match node.proxy_type {
            ProxyType::Shadowsocks => {
                entry.insert(
                    "type".to_string(),
                    serde_json::Value::String("ss".to_string()),
                );
                entry.insert(
                    "cipher".to_string(),
                    serde_json::Value::String(node.encrypt_method.clone()),
                );
                entry.insert(
                    "password".to_string(),
                    serde_json::Value::String(node.password.clone()),
                );
            }
            ProxyType::VMess => {
                entry.insert(
                    "type".to_string(),
                    serde_json::Value::String("vmess".to_string()),
                );
                entry.insert(
                    "uuid".to_string(),
                    serde_json::Value::String(node.user_id.clone()),
                );
                entry.insert(
                    "alterId".to_string(),
                    serde_json::Value::Number(node.alter_id.into()),
                );
                entry.insert(
                    "cipher".to_string(),
                    serde_json::Value::String(if node.encrypt_method.is_empty() {
                        "auto".to_string()
                    } else {
                        node.encrypt_method.clone()
                    }),
                );
                entry.insert(
                    "network".to_string(),
                    serde_json::Value::String(node.transfer_protocol.clone()),
                );
                entry.insert("tls".to_string(), serde_json::Value::Bool(node.tls_secure));
                add_clash_transport_options(&mut entry, node);
            }
            ProxyType::Trojan => {
                entry.insert(
                    "type".to_string(),
                    serde_json::Value::String("trojan".to_string()),
                );
                entry.insert(
                    "password".to_string(),
                    serde_json::Value::String(node.password.clone()),
                );
                add_clash_trojan_options(&mut entry, node);
            }
            ProxyType::ShadowsocksR => {
                entry.insert(
                    "type".to_string(),
                    serde_json::Value::String("ssr".to_string()),
                );
                entry.insert(
                    "cipher".to_string(),
                    serde_json::Value::String(node.encrypt_method.clone()),
                );
                entry.insert(
                    "password".to_string(),
                    serde_json::Value::String(node.password.clone()),
                );
                entry.insert(
                    "protocol".to_string(),
                    serde_json::Value::String(node.protocol.clone()),
                );
                entry.insert(
                    "obfs".to_string(),
                    serde_json::Value::String(node.obfs.clone()),
                );
                entry.insert(
                    "protocol-param".to_string(),
                    serde_json::Value::String(node.protocol_param.clone()),
                );
                entry.insert(
                    "obfs-param".to_string(),
                    serde_json::Value::String(node.obfs_param.clone()),
                );
            }
            ProxyType::Snell => {
                entry.insert(
                    "type".to_string(),
                    serde_json::Value::String("snell".to_string()),
                );
                entry.insert(
                    "psk".to_string(),
                    serde_json::Value::String(node.password.clone()),
                );
                if node.snell_version > 0 {
                    entry.insert(
                        "version".to_string(),
                        serde_json::Value::Number(node.snell_version.into()),
                    );
                }
                if !node.obfs.is_empty() || !node.host.is_empty() {
                    let mut obfs_opts = serde_json::Map::new();
                    if !node.obfs.is_empty() {
                        obfs_opts.insert(
                            "mode".to_string(),
                            serde_json::Value::String(node.obfs.clone()),
                        );
                    }
                    if !node.host.is_empty() {
                        obfs_opts.insert(
                            "host".to_string(),
                            serde_json::Value::String(node.host.clone()),
                        );
                    }
                    entry.insert(
                        "obfs-opts".to_string(),
                        serde_json::Value::Object(obfs_opts),
                    );
                }
            }
            ProxyType::Socks5 => {
                entry.insert(
                    "type".to_string(),
                    serde_json::Value::String("socks5".to_string()),
                );
                if !node.username.is_empty() {
                    entry.insert(
                        "username".to_string(),
                        serde_json::Value::String(node.username.clone()),
                    );
                }
                if !node.password.is_empty() {
                    entry.insert(
                        "password".to_string(),
                        serde_json::Value::String(node.password.clone()),
                    );
                }
            }
            ProxyType::WireGuard => {
                entry.insert(
                    "type".to_string(),
                    serde_json::Value::String("wireguard".to_string()),
                );
                entry.insert(
                    "ip".to_string(),
                    serde_json::Value::String(node.self_ip.clone()),
                );
                if !node.self_ipv6.is_empty() {
                    entry.insert(
                        "ipv6".to_string(),
                        serde_json::Value::String(node.self_ipv6.clone()),
                    );
                }
                entry.insert(
                    "private-key".to_string(),
                    serde_json::Value::String(node.private_key.clone()),
                );
                entry.insert(
                    "public-key".to_string(),
                    serde_json::Value::String(node.public_key.clone()),
                );
                if !node.pre_shared_key.is_empty() {
                    entry.insert(
                        "preshared-key".to_string(),
                        serde_json::Value::String(node.pre_shared_key.clone()),
                    );
                }
                if !node.dns_servers.is_empty() {
                    entry.insert(
                        "dns".to_string(),
                        serde_json::Value::Array(
                            node.dns_servers
                                .iter()
                                .cloned()
                                .map(serde_json::Value::String)
                                .collect(),
                        ),
                    );
                }
                if node.mtu > 0 {
                    entry.insert(
                        "mtu".to_string(),
                        serde_json::Value::Number(node.mtu.into()),
                    );
                }
            }
            ProxyType::Hysteria => {
                entry.insert(
                    "type".to_string(),
                    serde_json::Value::String("hysteria".to_string()),
                );
                if !node.protocol.is_empty() {
                    entry.insert(
                        "protocol".to_string(),
                        serde_json::Value::String(node.protocol.clone()),
                    );
                }
                if !node.auth_str.is_empty() {
                    entry.insert(
                        "auth-str".to_string(),
                        serde_json::Value::String(node.auth_str.clone()),
                    );
                }
                if !node.obfs_param.is_empty() {
                    entry.insert(
                        "obfs-protocol".to_string(),
                        serde_json::Value::String(node.obfs_param.clone()),
                    );
                }
                if !node.up.is_empty() {
                    entry.insert("up".to_string(), serde_json::Value::String(node.up.clone()));
                }
                if node.up_speed > 0 {
                    entry.insert(
                        "up-speed".to_string(),
                        serde_json::Value::Number(node.up_speed.into()),
                    );
                }
                if !node.down.is_empty() {
                    entry.insert(
                        "down".to_string(),
                        serde_json::Value::String(node.down.clone()),
                    );
                }
                if node.down_speed > 0 {
                    entry.insert(
                        "down-speed".to_string(),
                        serde_json::Value::Number(node.down_speed.into()),
                    );
                }
                if !node.obfs.is_empty() {
                    entry.insert(
                        "obfs".to_string(),
                        serde_json::Value::String(node.obfs.clone()),
                    );
                }
                if !node.sni.is_empty() {
                    entry.insert(
                        "sni".to_string(),
                        serde_json::Value::String(node.sni.clone()),
                    );
                }
                if !node.fingerprint.is_empty() {
                    entry.insert(
                        "fingerprint".to_string(),
                        serde_json::Value::String(node.fingerprint.clone()),
                    );
                }
                add_clash_alpn(&mut entry, node);
                entry.insert(
                    "skip-cert-verify".to_string(),
                    serde_json::Value::Bool(node.allow_insecure.get(false)),
                );
            }
            ProxyType::Hysteria2 => {
                entry.insert(
                    "type".to_string(),
                    serde_json::Value::String("hysteria2".to_string()),
                );
                entry.insert(
                    "password".to_string(),
                    serde_json::Value::String(node.password.clone()),
                );
                if !node.up.is_empty() {
                    entry.insert("up".to_string(), serde_json::Value::String(node.up.clone()));
                }
                if !node.down.is_empty() {
                    entry.insert(
                        "down".to_string(),
                        serde_json::Value::String(node.down.clone()),
                    );
                }
                if !node.obfs.is_empty() {
                    entry.insert(
                        "obfs".to_string(),
                        serde_json::Value::String(node.obfs.clone()),
                    );
                }
                if !node.obfs_param.is_empty() {
                    entry.insert(
                        "obfs-password".to_string(),
                        serde_json::Value::String(node.obfs_param.clone()),
                    );
                }
                if !node.sni.is_empty() {
                    entry.insert(
                        "sni".to_string(),
                        serde_json::Value::String(node.sni.clone()),
                    );
                }
                if !node.fingerprint.is_empty() {
                    entry.insert(
                        "fingerprint".to_string(),
                        serde_json::Value::String(node.fingerprint.clone()),
                    );
                }
                add_clash_alpn(&mut entry, node);
                entry.insert(
                    "skip-cert-verify".to_string(),
                    serde_json::Value::Bool(node.allow_insecure.get(false)),
                );
            }
            ProxyType::Http | ProxyType::Https => {
                entry.insert(
                    "type".to_string(),
                    serde_json::Value::String("http".to_string()),
                );
                if !node.username.is_empty() {
                    entry.insert(
                        "username".to_string(),
                        serde_json::Value::String(node.username.clone()),
                    );
                }
                if !node.password.is_empty() {
                    entry.insert(
                        "password".to_string(),
                        serde_json::Value::String(node.password.clone()),
                    );
                }
                entry.insert(
                    "tls".to_string(),
                    serde_json::Value::Bool(node.proxy_type == ProxyType::Https),
                );
            }
            ProxyType::Unknown => continue,
        }
        add_clash_common_options(&mut entry, node);
        proxies.push(serde_json::Value::Object(entry));
    }
    if options.nodelist.get(false) {
        return serde_yaml::to_string(&serde_json::json!({ "proxies": proxies }))
            .map_err(|err| Error::Parse(err.to_string()));
    }
    let mut generated = serde_json::Map::new();
    generated.insert("proxies".to_string(), serde_json::Value::Array(proxies));
    generated.insert(
        "proxy-groups".to_string(),
        serde_json::Value::Array(clash_proxy_groups_refs(&export_nodes, settings)),
    );
    generated.insert(
        "rules".to_string(),
        serde_json::Value::Array(
            clash_rules(settings, options)
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        ),
    );
    if let Some(providers) = clash_rule_providers(settings, options) {
        generated.insert(
            "rule-providers".to_string(),
            serde_json::Value::Object(providers),
        );
    }
    let output = merge_clash_base(serde_json::Value::Object(generated), settings)?;
    serde_yaml::to_string(&output).map_err(|err| Error::Parse(err.to_string()))
}

fn is_deprecated_for_clash(node: &Proxy, clash_r: bool, options: &ConvertOptions) -> bool {
    if !options.filter_deprecated.get(false) {
        return false;
    }
    match node.proxy_type {
        ProxyType::Shadowsocks => node.encrypt_method == "chacha20",
        ProxyType::ShadowsocksR => {
            (!clash_r && !CLASH_SSR_CIPHERS.contains(&node.encrypt_method.as_str()))
                || !CLASHR_PROTOCOLS.contains(&node.protocol.as_str())
                || !CLASHR_OBFS.contains(&node.obfs.as_str())
        }
        _ => false,
    }
}

const CLASH_SSR_CIPHERS: &[&str] = &[
    "rc4-md5",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "chacha20-ietf",
    "xchacha20",
    "none",
];

const CLASHR_PROTOCOLS: &[&str] = &[
    "origin",
    "auth_sha1_v4",
    "auth_aes128_md5",
    "auth_aes128_sha1",
    "auth_chain_a",
    "auth_chain_b",
];

const CLASHR_OBFS: &[&str] = &[
    "plain",
    "http_simple",
    "http_post",
    "random_head",
    "tls1.2_ticket_auth",
    "tls1.2_ticket_fastauth",
];

fn add_clash_common_options(entry: &mut serde_json::Map<String, serde_json::Value>, node: &Proxy) {
    if !node.udp.is_undef() {
        entry.insert(
            "udp".to_string(),
            serde_json::Value::Bool(node.udp.get(false)),
        );
    }
    if !node.tcp_fast_open.is_undef() {
        entry.insert(
            "tfo".to_string(),
            serde_json::Value::Bool(node.tcp_fast_open.get(false)),
        );
    }
    if !node.allow_insecure.is_undef() && !entry.contains_key("skip-cert-verify") {
        entry.insert(
            "skip-cert-verify".to_string(),
            serde_json::Value::Bool(node.allow_insecure.get(false)),
        );
    }
    if !node.tls13.is_undef() {
        entry.insert(
            "tls13".to_string(),
            serde_json::Value::Bool(node.tls13.get(false)),
        );
    }
}

fn add_clash_alpn(entry: &mut serde_json::Map<String, serde_json::Value>, node: &Proxy) {
    if !node.alpn.is_empty() {
        entry.insert(
            "alpn".to_string(),
            serde_json::Value::Array(
                node.alpn
                    .iter()
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
}

fn add_clash_transport_options(
    entry: &mut serde_json::Map<String, serde_json::Value>,
    node: &Proxy,
) {
    if !node.server_name.is_empty() {
        entry.insert(
            "servername".to_string(),
            serde_json::Value::String(node.server_name.clone()),
        );
    }
    match node.transfer_protocol.as_str() {
        "ws" => {
            let mut ws_opts = serde_json::Map::new();
            if !node.path.is_empty() {
                ws_opts.insert(
                    "path".to_string(),
                    serde_json::Value::String(node.path.clone()),
                );
            }
            if !node.host.is_empty() || !node.edge.is_empty() {
                let mut headers = serde_json::Map::new();
                if !node.host.is_empty() {
                    headers.insert(
                        "Host".to_string(),
                        serde_json::Value::String(node.host.clone()),
                    );
                }
                if !node.edge.is_empty() {
                    headers.insert(
                        "Edge".to_string(),
                        serde_json::Value::String(node.edge.clone()),
                    );
                }
                ws_opts.insert("headers".to_string(), serde_json::Value::Object(headers));
            }
            if !ws_opts.is_empty() {
                entry.insert("ws-opts".to_string(), serde_json::Value::Object(ws_opts));
            }
        }
        "h2" => {
            let mut h2_opts = serde_json::Map::new();
            if !node.path.is_empty() {
                h2_opts.insert(
                    "path".to_string(),
                    serde_json::Value::String(node.path.clone()),
                );
            }
            if !node.host.is_empty() {
                h2_opts.insert(
                    "host".to_string(),
                    serde_json::Value::Array(vec![serde_json::Value::String(node.host.clone())]),
                );
            }
            if !h2_opts.is_empty() {
                entry.insert("h2-opts".to_string(), serde_json::Value::Object(h2_opts));
            }
        }
        "grpc" if !node.path.is_empty() => {
            let mut grpc_opts = serde_json::Map::new();
            grpc_opts.insert(
                "grpc-service-name".to_string(),
                serde_json::Value::String(node.path.clone()),
            );
            entry.insert(
                "grpc-opts".to_string(),
                serde_json::Value::Object(grpc_opts),
            );
        }
        _ => {}
    }
}

fn add_clash_trojan_options(entry: &mut serde_json::Map<String, serde_json::Value>, node: &Proxy) {
    if !node.sni.is_empty() {
        entry.insert(
            "sni".to_string(),
            serde_json::Value::String(node.sni.clone()),
        );
    }
    match node.transfer_protocol.as_str() {
        "ws" => {
            entry.insert(
                "network".to_string(),
                serde_json::Value::String("ws".to_string()),
            );
            let mut ws_opts = serde_json::Map::new();
            if !node.path.is_empty() {
                ws_opts.insert(
                    "path".to_string(),
                    serde_json::Value::String(node.path.clone()),
                );
            }
            if !node.host.is_empty() {
                let mut headers = serde_json::Map::new();
                headers.insert(
                    "Host".to_string(),
                    serde_json::Value::String(node.host.clone()),
                );
                ws_opts.insert("headers".to_string(), serde_json::Value::Object(headers));
            }
            if !ws_opts.is_empty() {
                entry.insert("ws-opts".to_string(), serde_json::Value::Object(ws_opts));
            }
        }
        "grpc" => {
            entry.insert(
                "network".to_string(),
                serde_json::Value::String("grpc".to_string()),
            );
            if !node.path.is_empty() {
                let mut grpc_opts = serde_json::Map::new();
                grpc_opts.insert(
                    "grpc-service-name".to_string(),
                    serde_json::Value::String(node.path.clone()),
                );
                entry.insert(
                    "grpc-opts".to_string(),
                    serde_json::Value::Object(grpc_opts),
                );
            }
        }
        _ => {}
    }
}

fn merge_clash_base(
    generated: serde_json::Value,
    settings: Option<&Settings>,
) -> Result<serde_json::Value> {
    let Some(settings) = settings else {
        return Ok(generated);
    };
    if settings.clash_rule_base.trim().is_empty() || !looks_like_yaml_map(&settings.clash_rule_base)
    {
        return Ok(generated);
    }
    let mut base: serde_json::Value = serde_yaml::from_str(&settings.clash_rule_base)
        .map_err(|err| Error::Parse(format!("invalid clash_rule_base yaml: {err}")))?;
    let Some(base_object) = base.as_object_mut() else {
        return Ok(generated);
    };
    let generated_object = generated
        .as_object()
        .ok_or_else(|| Error::Parse("generated clash output is not an object".to_string()))?;
    for key in ["proxies", "proxy-groups", "rules"] {
        if let Some(value) = generated_object.get(key) {
            base_object.insert(key.to_string(), value.clone());
        }
    }
    Ok(base)
}

fn looks_like_yaml_map(value: &str) -> bool {
    value.lines().any(|line| {
        let trimmed = line.trim_start();
        !trimmed.starts_with('#') && trimmed.contains(':')
    })
}

fn clash_proxy_groups_refs(
    nodes: &[&Proxy],
    settings: Option<&Settings>,
) -> Vec<serde_json::Value> {
    let node_names = nodes
        .iter()
        .map(|node| node.remark.clone())
        .collect::<Vec<_>>();
    let Some(settings) = settings else {
        return vec![serde_json::json!({
            "name": "Proxy",
            "type": "select",
            "proxies": node_names,
        })];
    };
    if settings.custom_proxy_groups.is_empty() {
        return vec![serde_json::json!({
            "name": "Proxy",
            "type": "select",
            "proxies": node_names,
        })];
    }
    settings
        .custom_proxy_groups
        .iter()
        .map(|group| {
            let mut proxies = expand_group_rules_refs(&group.proxies, nodes);
            if proxies.is_empty() {
                proxies = node_names.clone();
            }
            let mut object = serde_json::Map::new();
            object.insert(
                "name".to_string(),
                serde_json::Value::String(group.name.clone()),
            );
            object.insert(
                "type".to_string(),
                serde_json::Value::String(group.group_type.clone()),
            );
            object.insert(
                "proxies".to_string(),
                serde_json::Value::Array(
                    proxies
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect::<Vec<_>>(),
                ),
            );
            if !group.providers.is_empty() {
                object.insert(
                    "use".to_string(),
                    serde_json::Value::Array(
                        group
                            .providers
                            .iter()
                            .cloned()
                            .map(serde_json::Value::String)
                            .collect::<Vec<_>>(),
                    ),
                );
            }
            if !group.url.is_empty() {
                object.insert(
                    "url".to_string(),
                    serde_json::Value::String(group.url.clone()),
                );
            }
            if group.interval > 0 {
                object.insert(
                    "interval".to_string(),
                    serde_json::Value::Number(group.interval.into()),
                );
            }
            if group.timeout > 0 {
                object.insert(
                    "timeout".to_string(),
                    serde_json::Value::Number(group.timeout.into()),
                );
            }
            if group.tolerance > 0 {
                object.insert(
                    "tolerance".to_string(),
                    serde_json::Value::Number(group.tolerance.into()),
                );
            }
            if !group.disable_udp.is_undef() {
                object.insert(
                    "disable-udp".to_string(),
                    serde_json::Value::Bool(group.disable_udp.get(false)),
                );
            }
            serde_json::Value::Object(object)
        })
        .collect()
}

fn expand_group_rules_refs(rules: &[String], nodes: &[&Proxy]) -> Vec<String> {
    let mut names = Vec::new();
    for rule in rules {
        if let Some(name) = rule.strip_prefix("[]") {
            names.push(name.to_string());
        } else if rule == ".*" {
            names.extend(nodes.iter().map(|node| node.remark.clone()));
        } else if let Some(group_name) = rule.strip_prefix("!!GROUP=") {
            names.extend(
                nodes
                    .iter()
                    .filter(|node| node.group == group_name)
                    .map(|node| node.remark.clone()),
            );
        } else if let Ok(regex) = Regex::new(rule) {
            names.extend(
                nodes
                    .iter()
                    .filter(|node| regex.is_match(&node.remark))
                    .map(|node| node.remark.clone()),
            );
        } else {
            names.push(rule.clone());
        }
    }
    names.dedup();
    names
}

fn clash_rules(settings: Option<&Settings>, options: &ConvertOptions) -> Vec<String> {
    let Some(settings) = settings else {
        return vec!["MATCH,Proxy".to_string()];
    };
    let mut rules = settings
        .rulesets
        .iter()
        .map(|ruleset| clash_rule_from_config(ruleset, settings, options))
        .collect::<Vec<_>>();
    if rules.is_empty() {
        rules.push("MATCH,Proxy".to_string());
    }
    rules
}

fn clash_rule_from_config(
    ruleset: &crate::model::RulesetConfig,
    settings: &Settings,
    options: &ConvertOptions,
) -> String {
    if let Some(rule) = ruleset.url.strip_prefix("[]") {
        if rule.eq_ignore_ascii_case("FINAL") {
            return format!("MATCH,{}", ruleset.group);
        }
        return format!("{rule},{}", ruleset.group);
    }
    if clash_should_use_rule_provider(ruleset, settings, options) {
        return format!(
            "RULE-SET,{},{}",
            clash_rule_provider_name(ruleset),
            ruleset.group
        );
    }
    let path = ruleset
        .url
        .strip_prefix("surge:")
        .or_else(|| ruleset.url.strip_prefix("quanx:"))
        .or_else(|| ruleset.url.strip_prefix("clash-domain:"))
        .or_else(|| ruleset.url.strip_prefix("clash-ipcidr:"))
        .or_else(|| ruleset.url.strip_prefix("clash-classic:"))
        .unwrap_or(&ruleset.url);
    format!("RULE-SET,{path},{}", ruleset.group)
}

fn clash_rule_providers(
    settings: Option<&Settings>,
    options: &ConvertOptions,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    let settings = settings?;
    let mut providers = serde_json::Map::new();
    for ruleset in &settings.rulesets {
        if !clash_should_use_rule_provider(ruleset, settings, options) {
            continue;
        }
        let Some(provider) = clash_rule_provider(ruleset, settings, options) else {
            continue;
        };
        let mut name = clash_rule_provider_name(ruleset);
        if providers.contains_key(&name) {
            let base = name.clone();
            let mut index = 2;
            while providers.contains_key(&name) {
                name = format!("{base} {index}");
                index += 1;
            }
        }
        providers.insert(name, serde_json::Value::Object(provider));
    }
    (!providers.is_empty()).then_some(providers)
}

fn clash_should_use_rule_provider(
    ruleset: &crate::model::RulesetConfig,
    settings: &Settings,
    options: &ConvertOptions,
) -> bool {
    !options.expand_rulesets.get(true)
        && !settings.managed_config_prefix.is_empty()
        && clash_ruleset_provider_type(&ruleset.url).is_some()
}

fn clash_rule_provider(
    ruleset: &crate::model::RulesetConfig,
    settings: &Settings,
    options: &ConvertOptions,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    let behavior = clash_rule_provider_behavior(&ruleset.url, options)?;
    let rule_type = match behavior {
        "domain" => 3,
        "ipcidr" => 4,
        _ => 6,
    };
    let mut provider = serde_json::Map::new();
    provider.insert(
        "type".to_string(),
        serde_json::Value::String("http".to_string()),
    );
    provider.insert(
        "behavior".to_string(),
        serde_json::Value::String(behavior.to_string()),
    );
    provider.insert(
        "url".to_string(),
        serde_json::Value::String(format!(
            "{}/getruleset?type={rule_type}&url={}",
            settings.managed_config_prefix,
            url_safe_base64_encode(&ruleset.url)
        )),
    );
    provider.insert(
        "path".to_string(),
        serde_json::Value::String(clash_rule_provider_path(&ruleset.url, behavior)),
    );
    if ruleset.interval > 0 {
        provider.insert(
            "interval".to_string(),
            serde_json::Value::Number(ruleset.interval.into()),
        );
    }
    Some(provider)
}

fn clash_rule_provider_behavior(url: &str, options: &ConvertOptions) -> Option<&'static str> {
    if options.classic_ruleset.get(false) {
        return clash_ruleset_provider_type(url).map(|_| "classical");
    }
    if url.starts_with("clash-domain:") {
        Some("domain")
    } else if url.starts_with("clash-ipcidr:") {
        Some("ipcidr")
    } else if url.starts_with("clash-classic:") {
        Some("classical")
    } else {
        None
    }
}

fn clash_rule_provider_name(ruleset: &crate::model::RulesetConfig) -> String {
    let path = clash_ruleset_path(&ruleset.url);
    path.rsplit(['/', '\\'])
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or(path)
        .to_string()
}

fn clash_rule_provider_path(url: &str, behavior: &str) -> String {
    let suffix = match behavior {
        "domain" => "_domain.yaml",
        "ipcidr" => "_ipcidr.yaml",
        _ => ".yaml",
    };
    format!("./providers/{}{suffix}", stable_ruleset_hash(url))
}

fn stable_ruleset_hash(input: &str) -> u64 {
    input.as_bytes().iter().fold(5381_u64, |hash, byte| {
        hash.wrapping_mul(33).wrapping_add(*byte as u64)
    })
}

fn clash_ruleset_path(url: &str) -> &str {
    url.strip_prefix("surge:")
        .or_else(|| url.strip_prefix("quanx:"))
        .or_else(|| url.strip_prefix("clash-domain:"))
        .or_else(|| url.strip_prefix("clash-ipcidr:"))
        .or_else(|| url.strip_prefix("clash-classic:"))
        .unwrap_or(url)
}

fn clash_ruleset_provider_type(url: &str) -> Option<u8> {
    if url.starts_with("clash-domain:") {
        Some(3)
    } else if url.starts_with("clash-ipcidr:") {
        Some(4)
    } else if url.starts_with("clash-classic:") {
        Some(6)
    } else {
        None
    }
}

fn export_singbox(
    nodes: &[Proxy],
    settings: Option<&Settings>,
    options: &ConvertOptions,
) -> Result<String> {
    let outbounds: Vec<_> = nodes.iter().map(singbox_outbound).collect();
    if options.nodelist.get(false) {
        return serde_json::to_string_pretty(&serde_json::json!({ "outbounds": outbounds }))
            .map_err(|err| Error::Parse(err.to_string()));
    }
    let output = merge_singbox_base(outbounds, nodes, settings)?;
    serde_json::to_string_pretty(&output).map_err(|err| Error::Parse(err.to_string()))
}

fn merge_singbox_base(
    outbounds: Vec<serde_json::Value>,
    nodes: &[Proxy],
    settings: Option<&Settings>,
) -> Result<serde_json::Value> {
    let Some(settings) = settings else {
        return Ok(serde_json::json!({ "outbounds": outbounds }));
    };
    let base = settings.singbox_rule_base.trim();
    if base.is_empty() || !base.starts_with('{') {
        return Ok(serde_json::json!({ "outbounds": outbounds }));
    }
    let mut base: serde_json::Value = serde_json::from_str(base)
        .map_err(|err| Error::Parse(format!("invalid singbox_rule_base json: {err}")))?;
    let Some(object) = base.as_object_mut() else {
        return Ok(serde_json::json!({ "outbounds": outbounds }));
    };
    let mut merged_outbounds = vec![
        serde_json::json!({"type": "direct", "tag": "DIRECT"}),
        serde_json::json!({"type": "block", "tag": "REJECT"}),
        serde_json::json!({"type": "dns", "tag": "dns-out"}),
    ];
    merged_outbounds.extend(outbounds);
    let node_refs = nodes.iter().collect::<Vec<_>>();
    for group in &settings.custom_proxy_groups {
        let members = expand_group_rules_refs(&group.proxies, &node_refs);
        let members = if members.is_empty() {
            nodes.iter().map(|node| node.remark.clone()).collect()
        } else {
            members
        };
        let group_type = if group.group_type == "url-test" {
            "urltest"
        } else {
            "selector"
        };
        let mut outbound = serde_json::Map::new();
        outbound.insert(
            "type".to_string(),
            serde_json::Value::String(group_type.to_string()),
        );
        outbound.insert(
            "tag".to_string(),
            serde_json::Value::String(group.name.clone()),
        );
        outbound.insert(
            "outbounds".to_string(),
            serde_json::Value::Array(members.into_iter().map(serde_json::Value::String).collect()),
        );
        if group_type == "urltest" {
            if !group.url.is_empty() {
                outbound.insert(
                    "url".to_string(),
                    serde_json::Value::String(group.url.clone()),
                );
            }
            if group.interval > 0 {
                outbound.insert(
                    "interval".to_string(),
                    serde_json::Value::String(format!("{}s", group.interval)),
                );
            }
            if group.tolerance > 0 {
                outbound.insert(
                    "tolerance".to_string(),
                    serde_json::Value::Number(group.tolerance.into()),
                );
            }
        }
        merged_outbounds.push(serde_json::Value::Object(outbound));
    }
    if settings.custom_proxy_groups.is_empty() {
        merged_outbounds.push(serde_json::json!({
            "type": "selector",
            "tag": "Proxy",
            "outbounds": nodes.iter().map(|node| node.remark.clone()).collect::<Vec<_>>()
        }));
    }
    let mut global = vec![serde_json::Value::String("DIRECT".to_string())];
    global.extend(
        nodes
            .iter()
            .map(|node| serde_json::Value::String(node.remark.clone())),
    );
    merged_outbounds.push(serde_json::json!({
        "type": "selector",
        "tag": "GLOBAL",
        "outbounds": global
    }));
    object.insert(
        "outbounds".to_string(),
        serde_json::Value::Array(merged_outbounds),
    );

    let route = object
        .entry("route".to_string())
        .or_insert_with(|| serde_json::json!({}));
    let route = route
        .as_object_mut()
        .ok_or_else(|| Error::Parse("sing-box route must be an object".to_string()))?;
    let mut rules = vec![
        serde_json::json!({"clash_mode": "Global", "outbound": "GLOBAL"}),
        serde_json::json!({"clash_mode": "Direct", "outbound": "DIRECT"}),
        serde_json::json!({"protocol": "dns", "outbound": "dns-out"}),
    ];
    if !settings.overwrite_original_rules {
        if let Some(existing) = route.get("rules").and_then(serde_json::Value::as_array) {
            rules.extend(existing.iter().cloned());
        }
    }
    for ruleset in &settings.rulesets {
        if let Some(rule) = ruleset.url.strip_prefix("[]") {
            if rule.eq_ignore_ascii_case("FINAL") {
                route.insert(
                    "final".to_string(),
                    serde_json::Value::String(ruleset.group.clone()),
                );
            } else if let Some(country) = rule.strip_prefix("GEOIP,") {
                rules.push(serde_json::json!({
                    "geoip": [country.to_ascii_lowercase()],
                    "outbound": ruleset.group
                }));
            } else if let Some(domain) = rule.strip_prefix("DOMAIN-SUFFIX,") {
                rules.push(serde_json::json!({
                    "domain_suffix": [domain],
                    "outbound": ruleset.group
                }));
            } else if let Some(domain) = rule.strip_prefix("DOMAIN,") {
                rules.push(serde_json::json!({
                    "domain": [domain],
                    "outbound": ruleset.group
                }));
            }
        }
    }
    route.insert("rules".to_string(), serde_json::Value::Array(rules));
    Ok(base)
}

fn singbox_outbound(node: &Proxy) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    object.insert(
        "type".to_string(),
        serde_json::Value::String(
            match node.proxy_type {
                ProxyType::Shadowsocks => "shadowsocks",
                ProxyType::ShadowsocksR => "shadowsocksr",
                ProxyType::VMess => "vmess",
                ProxyType::Trojan => "trojan",
                ProxyType::Snell => "snell",
                ProxyType::Socks5 => "socks",
                ProxyType::WireGuard => "wireguard",
                ProxyType::Hysteria => "hysteria",
                ProxyType::Hysteria2 => "hysteria2",
                _ => "http",
            }
            .to_string(),
        ),
    );
    object.insert(
        "tag".to_string(),
        serde_json::Value::String(node.remark.clone()),
    );
    object.insert(
        "server".to_string(),
        serde_json::Value::String(node.hostname.clone()),
    );
    object.insert(
        "server_port".to_string(),
        serde_json::Value::Number(node.port.into()),
    );
    match node.proxy_type {
        ProxyType::Snell => {
            object.insert(
                "password".to_string(),
                serde_json::Value::String(node.password.clone()),
            );
            if node.snell_version > 0 {
                object.insert(
                    "version".to_string(),
                    serde_json::Value::Number(node.snell_version.into()),
                );
            }
            if !node.obfs.is_empty() {
                object.insert(
                    "obfs".to_string(),
                    serde_json::Value::String(node.obfs.clone()),
                );
            }
            if !node.host.is_empty() {
                object.insert(
                    "obfs_host".to_string(),
                    serde_json::Value::String(node.host.clone()),
                );
            }
        }
        ProxyType::WireGuard => {
            object.insert(
                "local_address".to_string(),
                serde_json::Value::Array(
                    [node.self_ip.clone(), node.self_ipv6.clone()]
                        .into_iter()
                        .filter(|value| !value.is_empty())
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
            object.insert(
                "private_key".to_string(),
                serde_json::Value::String(node.private_key.clone()),
            );
            let mut peer = serde_json::Map::new();
            peer.insert(
                "server".to_string(),
                serde_json::Value::String(node.hostname.clone()),
            );
            peer.insert(
                "server_port".to_string(),
                serde_json::Value::Number(node.port.into()),
            );
            peer.insert(
                "public_key".to_string(),
                serde_json::Value::String(node.public_key.clone()),
            );
            if !node.pre_shared_key.is_empty() {
                peer.insert(
                    "pre_shared_key".to_string(),
                    serde_json::Value::String(node.pre_shared_key.clone()),
                );
            }
            let allowed_ips = comma_list_json(&node.allowed_ips);
            if !allowed_ips.is_empty() {
                peer.insert(
                    "allowed_ips".to_string(),
                    serde_json::Value::Array(allowed_ips),
                );
            }
            let reserved = comma_list_json(&node.client_id);
            if !reserved.is_empty() {
                peer.insert("reserved".to_string(), serde_json::Value::Array(reserved));
            }
            object.insert(
                "peers".to_string(),
                serde_json::Value::Array(vec![serde_json::Value::Object(peer)]),
            );
            if node.mtu > 0 {
                object.insert(
                    "mtu".to_string(),
                    serde_json::Value::Number(node.mtu.into()),
                );
            }
        }
        ProxyType::Hysteria => {
            if !node.up.is_empty() {
                object.insert(
                    "up_mbps".to_string(),
                    serde_json::Value::Number(node.up_speed.into()),
                );
            }
            if !node.down.is_empty() {
                object.insert(
                    "down_mbps".to_string(),
                    serde_json::Value::Number(node.down_speed.into()),
                );
            }
            if !node.auth_str.is_empty() {
                object.insert(
                    "auth_str".to_string(),
                    serde_json::Value::String(node.auth_str.clone()),
                );
                object.insert(
                    "auth".to_string(),
                    serde_json::Value::String(base64_encode(&node.auth_str)),
                );
            }
            if !node.obfs.is_empty() {
                object.insert(
                    "obfs".to_string(),
                    serde_json::Value::String(node.obfs.clone()),
                );
            }
            if node.recv_window_conn > 0 {
                object.insert(
                    "recv_window_conn".to_string(),
                    serde_json::Value::Number(node.recv_window_conn.into()),
                );
            }
            if node.recv_window > 0 {
                object.insert(
                    "recv_window".to_string(),
                    serde_json::Value::Number(node.recv_window.into()),
                );
            }
            if !node.disable_mtu_discovery.is_undef() {
                object.insert(
                    "disable_mtu_discovery".to_string(),
                    serde_json::Value::Bool(node.disable_mtu_discovery.get(false)),
                );
            }
            add_singbox_tls(&mut object, node);
        }
        ProxyType::Hysteria2 => {
            object.insert(
                "password".to_string(),
                serde_json::Value::String(node.password.clone()),
            );
            if !node.ports.is_empty() {
                object.insert(
                    "server_ports".to_string(),
                    serde_json::Value::String(node.ports.clone()),
                );
            }
            if !node.up.is_empty() {
                object.insert(
                    "up_mbps".to_string(),
                    serde_json::Value::Number(node.up_speed.into()),
                );
            }
            if !node.down.is_empty() {
                object.insert(
                    "down_mbps".to_string(),
                    serde_json::Value::Number(node.down_speed.into()),
                );
            }
            if !node.obfs.is_empty() {
                let mut obfs = serde_json::Map::new();
                obfs.insert(
                    "type".to_string(),
                    serde_json::Value::String(node.obfs.clone()),
                );
                if !node.obfs_param.is_empty() {
                    obfs.insert(
                        "password".to_string(),
                        serde_json::Value::String(node.obfs_param.clone()),
                    );
                }
                object.insert("obfs".to_string(), serde_json::Value::Object(obfs));
            }
            if node.hop_interval > 0 {
                object.insert(
                    "hop_interval".to_string(),
                    serde_json::Value::String(format!("{}s", node.hop_interval)),
                );
            }
            add_singbox_tls(&mut object, node);
        }
        ProxyType::Shadowsocks => {
            object.insert(
                "method".to_string(),
                serde_json::Value::String(node.encrypt_method.clone()),
            );
            object.insert(
                "password".to_string(),
                serde_json::Value::String(node.password.clone()),
            );
            if !node.plugin.is_empty() && !node.plugin_option.is_empty() {
                object.insert(
                    "plugin".to_string(),
                    serde_json::Value::String(if node.plugin == "simple-obfs" {
                        "obfs-local".to_string()
                    } else {
                        node.plugin.clone()
                    }),
                );
                object.insert(
                    "plugin_opts".to_string(),
                    serde_json::Value::String(node.plugin_option.clone()),
                );
            }
        }
        ProxyType::ShadowsocksR => {
            object.insert(
                "method".to_string(),
                serde_json::Value::String(node.encrypt_method.clone()),
            );
            object.insert(
                "password".to_string(),
                serde_json::Value::String(node.password.clone()),
            );
            object.insert(
                "protocol".to_string(),
                serde_json::Value::String(node.protocol.clone()),
            );
            object.insert(
                "protocol_param".to_string(),
                serde_json::Value::String(node.protocol_param.clone()),
            );
            object.insert(
                "obfs".to_string(),
                serde_json::Value::String(node.obfs.clone()),
            );
            object.insert(
                "obfs_param".to_string(),
                serde_json::Value::String(node.obfs_param.clone()),
            );
        }
        ProxyType::VMess => {
            object.insert(
                "uuid".to_string(),
                serde_json::Value::String(node.user_id.clone()),
            );
            object.insert(
                "alter_id".to_string(),
                serde_json::Value::Number(node.alter_id.into()),
            );
            object.insert(
                "security".to_string(),
                serde_json::Value::String(node.encrypt_method.clone()),
            );
            add_singbox_transport(&mut object, node);
        }
        ProxyType::Trojan => {
            object.insert(
                "password".to_string(),
                serde_json::Value::String(node.password.clone()),
            );
            add_singbox_transport(&mut object, node);
        }
        ProxyType::Socks5 => {
            object.insert(
                "version".to_string(),
                serde_json::Value::String("5".to_string()),
            );
            object.insert(
                "username".to_string(),
                serde_json::Value::String(node.username.clone()),
            );
            object.insert(
                "password".to_string(),
                serde_json::Value::String(node.password.clone()),
            );
        }
        ProxyType::Http | ProxyType::Https => {
            object.insert(
                "username".to_string(),
                serde_json::Value::String(node.username.clone()),
            );
            object.insert(
                "password".to_string(),
                serde_json::Value::String(node.password.clone()),
            );
        }
        _ => {}
    }
    if !node.udp.is_undef() && !node.udp.get(true) {
        object.insert(
            "network".to_string(),
            serde_json::Value::String("tcp".to_string()),
        );
    }
    if !node.tcp_fast_open.is_undef() {
        object.insert(
            "tcp_fast_open".to_string(),
            serde_json::Value::Bool(node.tcp_fast_open.get(false)),
        );
    }
    if matches!(
        node.proxy_type,
        ProxyType::VMess | ProxyType::Trojan | ProxyType::Https
    ) && (node.tls_secure || !node.allow_insecure.is_undef())
    {
        add_singbox_stream_tls(&mut object, node);
    }
    serde_json::Value::Object(object)
}

fn add_singbox_tls(object: &mut serde_json::Map<String, serde_json::Value>, node: &Proxy) {
    let mut tls = serde_json::Map::new();
    tls.insert("enabled".to_string(), serde_json::Value::Bool(true));
    if !node.allow_insecure.is_undef() {
        tls.insert(
            "insecure".to_string(),
            serde_json::Value::Bool(node.allow_insecure.get(false)),
        );
    }
    if !node.alpn.is_empty() {
        tls.insert(
            "alpn".to_string(),
            serde_json::Value::Array(
                node.alpn
                    .iter()
                    .take(1)
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    if !node.ca.is_empty() {
        tls.insert(
            "certificate".to_string(),
            serde_json::Value::String(node.ca.clone()),
        );
    }
    if !node.ca_str.is_empty() {
        tls.insert(
            "certificate".to_string(),
            serde_json::Value::String(node.ca_str.clone()),
        );
    }
    object.insert("tls".to_string(), serde_json::Value::Object(tls));
}

fn add_singbox_stream_tls(object: &mut serde_json::Map<String, serde_json::Value>, node: &Proxy) {
    let mut tls = serde_json::Map::new();
    tls.insert("enabled".to_string(), serde_json::Value::Bool(true));
    if !node.server_name.is_empty() {
        tls.insert(
            "server_name".to_string(),
            serde_json::Value::String(node.server_name.clone()),
        );
    } else if !node.host.is_empty() {
        tls.insert(
            "server_name".to_string(),
            serde_json::Value::String(node.host.clone()),
        );
    }
    tls.insert(
        "insecure".to_string(),
        serde_json::Value::Bool(node.allow_insecure.get(false)),
    );
    object.insert("tls".to_string(), serde_json::Value::Object(tls));
}

fn add_singbox_transport(object: &mut serde_json::Map<String, serde_json::Value>, node: &Proxy) {
    let mut transport = serde_json::Map::new();
    match node.transfer_protocol.as_str() {
        "http" | "ws" => {
            transport.insert(
                "type".to_string(),
                serde_json::Value::String(node.transfer_protocol.clone()),
            );
            transport.insert(
                "path".to_string(),
                serde_json::Value::String(if node.path.is_empty() {
                    "/".to_string()
                } else {
                    node.path.clone()
                }),
            );
            let mut headers = serde_json::Map::new();
            if !node.host.is_empty() {
                headers.insert(
                    "Host".to_string(),
                    serde_json::Value::String(node.host.clone()),
                );
            }
            if !node.edge.is_empty() {
                headers.insert(
                    "Edge".to_string(),
                    serde_json::Value::String(node.edge.clone()),
                );
            }
            transport.insert("headers".to_string(), serde_json::Value::Object(headers));
            if node.transfer_protocol == "http" && !node.host.is_empty() {
                transport.insert(
                    "host".to_string(),
                    serde_json::Value::String(node.host.clone()),
                );
            }
        }
        "grpc" => {
            transport.insert(
                "type".to_string(),
                serde_json::Value::String("grpc".to_string()),
            );
            if !node.path.is_empty() {
                transport.insert(
                    "service_name".to_string(),
                    serde_json::Value::String(node.path.clone()),
                );
            }
        }
        _ => {}
    }
    if !transport.is_empty() {
        object.insert(
            "transport".to_string(),
            serde_json::Value::Object(transport),
        );
    }
}

fn comma_list_json(value: &str) -> Vec<serde_json::Value> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| serde_json::Value::String(item.to_string()))
        .collect()
}

fn export_single_links(nodes: &[Proxy], proxy_type: ProxyType) -> String {
    let links = nodes
        .iter()
        .filter(|node| node.proxy_type == proxy_type)
        .filter_map(export_share_link)
        .collect::<Vec<_>>()
        .join("\n");
    base64_encode(&format!("{links}\n"))
}

fn export_share_link(node: &Proxy) -> Option<String> {
    match node.proxy_type {
        ProxyType::ShadowsocksR => {
            let main = format!(
                "{}:{}:{}:{}:{}:{}",
                node.hostname,
                node.port,
                node.protocol,
                node.encrypt_method,
                node.obfs,
                base64_encode(&node.password)
            );
            let query = format!(
                "remarks={}&group={}",
                base64_encode(&node.remark),
                base64_encode(&node.group)
            );
            Some(format!(
                "ssr://{}",
                base64_encode(&format!("{main}/?{query}"))
            ))
        }
        ProxyType::Shadowsocks => {
            let user = format!("{}:{}", node.encrypt_method, node.password);
            Some(format!(
                "ss://{}@{}:{}#{}",
                base64_encode(&user).trim_end_matches('='),
                node.hostname,
                node.port,
                node.remark
            ))
        }
        ProxyType::VMess => export_v2ray_links(std::slice::from_ref(node))
            .into_iter()
            .next(),
        ProxyType::Trojan => Some(trojan_share_link(node)),
        _ => None,
    }
}

fn trojan_share_link(node: &Proxy) -> String {
    let mut query = Vec::new();
    if !node.sni.is_empty() {
        query.push(format!("sni={}", crate::util::url_encode(&node.sni)));
    }
    if !node.transfer_protocol.is_empty() {
        query.push(format!(
            "type={}",
            crate::util::url_encode(&node.transfer_protocol)
        ));
    }
    let suffix = if query.is_empty() {
        String::new()
    } else {
        format!("?{}", query.join("&"))
    };
    format!(
        "trojan://{}@{}:{}{}#{}",
        crate::util::url_encode(&node.password),
        node.hostname,
        node.port,
        suffix,
        crate::util::url_encode(&node.remark)
    )
}

fn export_trojan_links(nodes: &[Proxy]) -> String {
    let links = nodes
        .iter()
        .filter(|node| node.proxy_type == ProxyType::Trojan)
        .map(trojan_share_link)
        .collect::<Vec<_>>()
        .join("\n");
    base64_encode(&format!("{links}\n"))
}

fn export_sssub(
    nodes: &[Proxy],
    settings: Option<&Settings>,
    options: &ConvertOptions,
) -> Result<String> {
    let mut entries = Vec::new();
    let base = sssub_base(settings)?;
    for node in nodes {
        if node.proxy_type != ProxyType::Shadowsocks {
            continue;
        }
        let mut entry = base.clone();
        let Some(object) = entry.as_object_mut() else {
            entry = serde_json::Value::Object(serde_json::Map::new());
            let object = entry.as_object_mut().expect("object was just created");
            fill_sssub_entry(object, node);
            entries.push(entry);
            continue;
        };
        fill_sssub_entry(object, node);
        entries.push(entry);
    }
    if options.nodelist.get(false) {
        return serde_json::to_string_pretty(&entries).map_err(|err| Error::Parse(err.to_string()));
    }
    serde_json::to_string_pretty(&entries).map_err(|err| Error::Parse(err.to_string()))
}

fn sssub_base(settings: Option<&Settings>) -> Result<serde_json::Value> {
    let Some(settings) = settings else {
        return Ok(serde_json::Value::Object(serde_json::Map::new()));
    };
    let base = settings.sssub_rule_base.trim();
    if base.is_empty() || !base.starts_with('{') {
        return Ok(serde_json::Value::Object(serde_json::Map::new()));
    }
    let value: serde_json::Value = serde_json::from_str(base)
        .map_err(|err| Error::Parse(format!("invalid sssub_rule_base json: {err}")))?;
    if value.is_object() {
        Ok(value)
    } else {
        Ok(serde_json::Value::Object(serde_json::Map::new()))
    }
}

fn fill_sssub_entry(object: &mut serde_json::Map<String, serde_json::Value>, node: &Proxy) {
    object.insert(
        "remarks".to_string(),
        serde_json::Value::String(node.remark.clone()),
    );
    object.insert(
        "server".to_string(),
        serde_json::Value::String(node.hostname.clone()),
    );
    object.insert(
        "server_port".to_string(),
        serde_json::Value::Number(node.port.into()),
    );
    object.insert(
        "method".to_string(),
        serde_json::Value::String(node.encrypt_method.clone()),
    );
    object.insert(
        "password".to_string(),
        serde_json::Value::String(node.password.clone()),
    );
    object.insert(
        "plugin".to_string(),
        serde_json::Value::String(if node.plugin == "simple-obfs" {
            "obfs-local".to_string()
        } else {
            node.plugin.clone()
        }),
    );
    object.insert(
        "plugin_opts".to_string(),
        serde_json::Value::String(node.plugin_option.clone()),
    );
}

fn export_ssd(nodes: &[Proxy]) -> Result<String> {
    let servers = nodes
        .iter()
        .filter(|node| node.proxy_type == ProxyType::Shadowsocks)
        .map(|node| {
            serde_json::json!({
                "server": node.hostname,
                "port": node.port,
                "encryption": node.encrypt_method,
                "password": node.password,
                "plugin": node.plugin,
                "plugin_options": node.plugin_option,
                "remarks": node.remark,
                "id": node.id,
            })
        })
        .collect::<Vec<_>>();
    let default_encryption = nodes
        .iter()
        .find(|node| node.proxy_type == ProxyType::Shadowsocks)
        .map(|node| node.encrypt_method.as_str())
        .unwrap_or("");
    let value = serde_json::json!({
        "airport": "SSD",
        "port": 1,
        "encryption": default_encryption,
        "password": "password",
        "servers": servers,
    });
    Ok(format!("ssd://{}", base64_encode(&value.to_string())))
}

fn export_v2ray_links(nodes: &[Proxy]) -> Vec<String> {
    nodes
        .iter()
        .filter(|node| node.proxy_type == ProxyType::VMess)
        .map(|node| {
            let value = serde_json::json!({
                "v": "2",
                "ps": node.remark,
                "add": node.hostname,
                "port": node.port.to_string(),
                "id": node.user_id,
                "aid": node.alter_id.to_string(),
                "net": node.transfer_protocol,
                "type": node.fake_type,
                "host": node.host,
                "path": node.path,
                "tls": if node.tls_secure { "tls" } else { "" },
            });
            format!("vmess://{}", base64_encode(&value.to_string()))
        })
        .collect()
}

fn export_surge(nodes: &[Proxy], surge_version: SurgeVersion, include_direct: bool) -> String {
    let proxies = nodes
        .iter()
        .map(|node| match node.proxy_type {
            ProxyType::Shadowsocks if surge_version == SurgeVersion::V2 => format!(
                "{} = custom, {}, {}, {}, {}, https://github.com/pobizhe/SSEncrypt/raw/master/SSEncrypt.module",
                node.remark, node.hostname, node.port, node.encrypt_method, node.password
            ),
            ProxyType::Shadowsocks => format!(
                "{} = ss, {}, {}, encrypt-method={}, password={}",
                node.remark, node.hostname, node.port, node.encrypt_method, node.password
            ),
            ProxyType::VMess if surge_version == SurgeVersion::V4 => format!(
                "{} = vmess, {}, {}, username={}, tls={}, vmess-aead={}, ws={}, ws-path={}, sni={}, ws-headers=Host:{}",
                node.remark,
                node.hostname,
                node.port,
                node.user_id,
                bool_word(node.tls_secure),
                bool_word(node.alter_id == 0),
                bool_word(node.transfer_protocol == "ws"),
                node.path,
                node.host,
                node.host
            ),
            ProxyType::Trojan if surge_version == SurgeVersion::V4 => format!(
                "{} = trojan, {}, {}, password={}, sni={}",
                node.remark, node.hostname, node.port, node.password, node.sni
            ),
            ProxyType::Snell => format!(
                "{} = snell, {}, {}, psk={}, obfs={}, obfs-host={}, version={}",
                node.remark,
                node.hostname,
                node.port,
                node.password,
                node.obfs,
                node.host,
                node.snell_version
            ),
            ProxyType::Socks5 => format!(
                "{} = socks5, {}, {}, username={}, password={}",
                node.remark, node.hostname, node.port, node.username, node.password
            ),
            ProxyType::Http | ProxyType::Https => format!(
                "{} = http, {}, {}, username={}, password={}, tls={}",
                node.remark,
                node.hostname,
                node.port,
                node.username,
                node.password,
                bool_word(node.proxy_type == ProxyType::Https)
            ),
            _ => String::new(),
        })
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    let direct = if include_direct {
        "DIRECT = direct\n"
    } else {
        ""
    };
    format!(
        "[Proxy]\n{direct}{proxies}\n\n[Proxy Group]\nProxy = select,{}\n\n[Rule]\nFINAL,Proxy",
        node_names(nodes)
    )
}

fn export_quan(nodes: &[Proxy], settings: Option<&Settings>) -> String {
    let servers = nodes
        .iter()
        .map(|node| match node.proxy_type {
            ProxyType::Shadowsocks => format!(
                "{} = shadowsocks, {}, {}, {}, \"{}\", group={}",
                node.remark,
                node.hostname,
                node.port,
                node.encrypt_method,
                node.password,
                non_empty_group(&node.group)
            ),
            ProxyType::VMess => format!(
                "{} = vmess, {}, {}, chacha20-ietf-poly1305, \"{}\", over-tls={}, certificate=1, obfs=ws, obfs-path=\"{}\", obfs-header=\"Host={}\"",
                node.remark, node.hostname, node.port, node.user_id, bool_word(node.tls_secure), node.path, node.host
            ),
            ProxyType::Trojan => format!(
                "{} = trojan, {}, {}, password={}, over-tls=true, tls-host={}",
                node.remark, node.hostname, node.port, node.password, node.sni
            ),
            _ => format!(
                "{} = http, {}, {}, {}, {}",
                node.remark, node.hostname, node.port, node.username, node.password
            ),
        })
        .collect::<Vec<_>>()
        .join("\n");
    let policy = base64_encode(&quan_policy_content(nodes, settings));
    format!(
        "[SERVER]\n{servers}\n\n[POLICY]\n{policy}\n\n[TCP]\n{}",
        text_rules(settings).join("\n")
    )
}

fn export_quanx(nodes: &[Proxy], settings: Option<&Settings>) -> String {
    let servers = nodes
        .iter()
        .map(|node| match node.proxy_type {
            ProxyType::Shadowsocks => format!(
                "shadowsocks = {}:{}, method={}, password={}, tag={}",
                node.hostname, node.port, node.encrypt_method, node.password, node.remark
            ),
            ProxyType::VMess => format!(
                "vmess={}, {}, method=none, password={}, obfs=wss, obfs-host={}, obfs-uri={}, tls-verification=false, tag={}",
                node.hostname, node.port, node.user_id, node.host, node.path, node.remark
            ),
            ProxyType::Trojan => format!(
                "trojan={}, {}, password={}, over-tls=true, tls-host={}, tag={}",
                node.hostname, node.port, node.password, node.sni, node.remark
            ),
            ProxyType::Socks5 => format!(
                "socks5={}, {}, username={}, password={}, tag={}",
                node.hostname, node.port, node.username, node.password, node.remark
            ),
            _ => format!(
                "http={}, {}, username={}, password={}, tag={}",
                node.hostname, node.port, node.username, node.password, node.remark
            ),
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "[policy]\n{}\n\n[server_local]\n{servers}\n\n[filter_local]\n{}",
        quanx_policy_lines(nodes, settings).join("\n"),
        text_rules(settings).join("\n")
    )
}

fn export_loon(nodes: &[Proxy]) -> String {
    let proxies = nodes
        .iter()
        .map(|node| match node.proxy_type {
            ProxyType::Shadowsocks => format!(
                "{} = Shadowsocks, {}, {}, {}, {}",
                node.remark, node.hostname, node.port, node.encrypt_method, node.password
            ),
            ProxyType::VMess => format!(
                "{} = VMess, {}, {}, {}, {}, transport={}, path={}, host={}",
                node.remark,
                node.hostname,
                node.port,
                node.user_id,
                node.alter_id,
                node.transfer_protocol,
                node.path,
                node.host
            ),
            ProxyType::Trojan => format!(
                "{} = Trojan, {}, {}, {}, tls-name={}",
                node.remark, node.hostname, node.port, node.password, node.sni
            ),
            ProxyType::Snell => format!(
                "{} = snell, {}, {}, psk={}, version={}",
                node.remark,
                node.hostname,
                node.port,
                node.password,
                node.snell_version.max(2)
            ),
            ProxyType::Socks5 => format!(
                "{} = Socks5, {}, {}, {}, {}",
                node.remark, node.hostname, node.port, node.username, node.password
            ),
            _ => format!(
                "{} = Http, {}, {}, {}, {}",
                node.remark, node.hostname, node.port, node.username, node.password
            ),
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "[Proxy]\n{proxies}\n\n[Proxy Group]\nProxy = select, {}\n\n[Rule]\nFINAL,Proxy",
        node_names(nodes)
    )
}

fn non_empty_group(group: &str) -> &str {
    if group.is_empty() {
        "SSProvider"
    } else {
        group
    }
}

fn text_rules(settings: Option<&Settings>) -> Vec<String> {
    let rules = settings
        .into_iter()
        .flat_map(|settings| settings.rulesets.iter())
        .map(|ruleset| {
            if let Some(rule) = ruleset.url.strip_prefix("[]") {
                format!("{rule},{}", ruleset.group)
            } else {
                format!("RULE-SET,{},{}", ruleset.url, ruleset.group)
            }
        })
        .collect::<Vec<_>>();
    if rules.is_empty() {
        vec!["FINAL,Proxy".to_string()]
    } else {
        rules
    }
}

fn quan_policy_content(nodes: &[Proxy], settings: Option<&Settings>) -> String {
    let names = node_names(nodes);
    let groups = settings
        .into_iter()
        .flat_map(|settings| settings.custom_proxy_groups.iter())
        .map(|group| {
            let group_type = match group.group_type.as_str() {
                "url-test" => "auto",
                "fallback" => "available",
                "load-balance" => "balance",
                _ => "static",
            };
            format!("{} : {group_type}, {names}", group.name)
        })
        .collect::<Vec<_>>();
    let groups = if groups.is_empty() {
        vec![format!("Proxy : static, {names}")]
    } else {
        groups
    };
    format!("{}\n{names}\n", groups.join("\n"))
}

fn quanx_policy_lines(nodes: &[Proxy], settings: Option<&Settings>) -> Vec<String> {
    let names = node_names(nodes);
    let groups = settings
        .into_iter()
        .flat_map(|settings| settings.custom_proxy_groups.iter())
        .map(|group| {
            let group_type = match group.group_type.as_str() {
                "url-test" => "url-latency-benchmark",
                "fallback" => "available",
                "load-balance" => "round-robin",
                _ => "static",
            };
            format!("{group_type}={}, {names}", group.name)
        })
        .collect::<Vec<_>>();
    if groups.is_empty() {
        vec![format!("static=Proxy, {names}")]
    } else {
        groups
    }
}

fn export_surfboard(nodes: &[Proxy], include_direct: bool) -> String {
    let proxies = export_surge(nodes, SurgeVersion::V4, include_direct);
    proxies.replace("[Proxy Group]", "[Proxy Group]\n")
}

fn export_mellow(nodes: &[Proxy]) -> String {
    let endpoints = nodes
        .iter()
        .filter_map(|node| {
            let link = export_share_link(node)?;
            let decoded = if node.proxy_type == ProxyType::Shadowsocks {
                let user = base64_encode(":").trim_end_matches('=').to_string();
                format!("ss://{user}@{}:{}", node.hostname, node.port)
            } else {
                link
            };
            Some(format!(
                "{}, {}, {}",
                node.remark,
                mellow_type(node),
                decoded
            ))
        })
        .collect::<Vec<_>>()
        .join("\n");
    let names = node_names(nodes);
    format!(
        "[Endpoint]\n{endpoints}\n\n[EndpointGroup]\nProxy, {names}, latency, interval=300, timeout=6\n\n[RoutingRule]\nFINAL,Proxy"
    )
}

fn mellow_type(node: &Proxy) -> &'static str {
    match node.proxy_type {
        ProxyType::Shadowsocks => "ss",
        ProxyType::VMess => "vmess",
        ProxyType::Trojan => "trojan",
        ProxyType::Socks5 => "socks",
        _ => "http",
    }
}

fn apply_text_rule_base(
    generated: String,
    target: Target,
    settings: Option<&Settings>,
    options: &ConvertOptions,
) -> String {
    if options.nodelist.get(false) {
        return generated;
    }
    let Some(base) = text_rule_base(settings, target) else {
        return generated;
    };
    let base = base.trim_end_matches('\n');
    if base.trim().is_empty() || !base.lines().any(is_section_header) {
        return generated;
    }
    match target {
        Target::Surge | Target::Surfboard | Target::Loon | Target::Mellow => {
            let mut merged = base.to_string();
            let mut applied = false;
            let sections = if target == Target::Mellow {
                ["[Endpoint]", "[EndpointGroup]", "[RoutingRule]"]
            } else {
                ["[Proxy]", "[Proxy Group]", "[Rule]"]
            };
            for (index, section) in sections.into_iter().enumerate() {
                if let Some(body) = section_body(&generated, section) {
                    merged = if index > 0
                        && settings.is_some_and(|settings| settings.overwrite_original_rules)
                    {
                        replace_section(&merged, section, &body)
                    } else {
                        append_to_section(&merged, section, &body)
                    };
                    applied = true;
                }
            }
            if applied {
                merged
            } else {
                append_block(base, &generated)
            }
        }
        Target::Quan => {
            let mut merged = base.to_string();
            for (index, section) in ["[SERVER]", "[POLICY]", "[TCP]"].into_iter().enumerate() {
                if let Some(body) = section_body(&generated, section) {
                    merged = if index > 0
                        && settings.is_some_and(|settings| settings.overwrite_original_rules)
                    {
                        replace_section(&merged, section, &body)
                    } else {
                        append_to_section(&merged, section, &body)
                    };
                }
            }
            merged
        }
        Target::QuanX => {
            let mut merged = base.to_string();
            for (index, section) in ["[policy]", "[server_local]", "[filter_local]"]
                .into_iter()
                .enumerate()
            {
                if let Some(body) = section_body(&generated, section) {
                    merged = if index != 1
                        && settings.is_some_and(|settings| settings.overwrite_original_rules)
                    {
                        replace_section(&merged, section, &body)
                    } else {
                        append_to_section(&merged, section, &body)
                    };
                }
            }
            merged
        }
        _ => generated,
    }
}

fn text_rule_base(settings: Option<&Settings>, target: Target) -> Option<&str> {
    let settings = settings?;
    match target {
        Target::Surge => Some(settings.surge_rule_base.as_str()),
        Target::Surfboard => Some(settings.surfboard_rule_base.as_str()),
        Target::Quan => Some(settings.quan_rule_base.as_str()),
        Target::QuanX => Some(settings.quanx_rule_base.as_str()),
        Target::Loon => Some(settings.loon_rule_base.as_str()),
        Target::Mellow => Some(settings.mellow_rule_base.as_str()),
        _ => None,
    }
}

fn append_to_section(config: &str, section: &str, body: &str) -> String {
    let body = body.trim_matches('\n');
    if body.is_empty() {
        return config.to_string();
    }
    let lines = config.lines().collect::<Vec<_>>();
    let mut result = Vec::with_capacity(lines.len() + body.lines().count() + 2);
    let mut in_target = false;
    let mut inserted = false;
    let section_lower = section.to_ascii_lowercase();
    for line in lines {
        let trimmed = line.trim();
        if in_target && is_section_header(trimmed) {
            push_body(&mut result, body);
            inserted = true;
            in_target = false;
        }
        result.push(line.to_string());
        if trimmed.eq_ignore_ascii_case(&section_lower) {
            in_target = true;
        }
    }
    if in_target && !inserted {
        push_body(&mut result, body);
        inserted = true;
    }
    if !inserted {
        if !result.is_empty() && !result.last().is_some_and(|line| line.trim().is_empty()) {
            result.push(String::new());
        }
        result.push(section.to_string());
        push_body(&mut result, body);
    }
    result.join("\n")
}

fn replace_section(config: &str, section: &str, body: &str) -> String {
    let target = section.trim().to_ascii_lowercase();
    let mut result = Vec::new();
    let mut found = false;
    let mut skipping = false;
    for line in config.lines() {
        let trimmed = line.trim();
        if is_section_header(trimmed) {
            if skipping {
                skipping = false;
            }
            if trimmed.to_ascii_lowercase() == target {
                found = true;
                skipping = true;
                result.push(line.to_string());
                if !body.trim().is_empty() {
                    result.extend(body.trim_matches('\n').lines().map(ToOwned::to_owned));
                }
                continue;
            }
        }
        if !skipping {
            result.push(line.to_string());
        }
    }
    if !found {
        if !result.is_empty() && !result.last().is_some_and(|line| line.is_empty()) {
            result.push(String::new());
        }
        result.push(section.to_string());
        result.extend(body.trim_matches('\n').lines().map(ToOwned::to_owned));
    }
    result.join("\n")
}

fn push_body(result: &mut Vec<String>, body: &str) {
    if !result.last().is_some_and(|line| line.trim().is_empty()) {
        result.push(String::new());
    }
    result.extend(body.lines().map(ToOwned::to_owned));
}

fn append_block(base: &str, generated: &str) -> String {
    if base.trim().is_empty() {
        generated.to_string()
    } else if generated.trim().is_empty() {
        base.to_string()
    } else {
        format!(
            "{}\n\n{}",
            base.trim_end_matches('\n'),
            generated.trim_matches('\n')
        )
    }
}

fn section_body(config: &str, section: &str) -> Option<String> {
    let mut found = false;
    let mut body = Vec::new();
    for line in config.lines() {
        let trimmed = line.trim();
        if found && is_section_header(trimmed) {
            break;
        }
        if found {
            body.push(line);
        } else if trimmed.eq_ignore_ascii_case(section) {
            found = true;
        }
    }
    let body = body.join("\n");
    let body = body.trim_matches('\n');
    if body.is_empty() {
        None
    } else {
        Some(body.to_string())
    }
}

fn is_section_header(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.len() > 2 && trimmed.starts_with('[') && trimmed.ends_with(']')
}

fn export_mixed(nodes: &[Proxy]) -> String {
    let links = nodes
        .iter()
        .filter_map(export_share_link)
        .collect::<Vec<_>>()
        .join("\n");
    base64_encode(&format!("{links}\n"))
}

fn split_fragment(input: &str) -> (&str, Option<String>) {
    if let Some((left, right)) = input.split_once('#') {
        (left, Some(crate::util::url_decode(right)))
    } else {
        (input, None)
    }
}

fn split_host_port(input: &str) -> Result<(String, u16)> {
    let (host, port) = input
        .rsplit_once(':')
        .ok_or_else(|| Error::Parse("missing host/port".to_string()))?;
    let port = port
        .parse()
        .map_err(|err| Error::Parse(format!("invalid port: {err}")))?;
    Ok((host.to_string(), port))
}

fn query_pairs(url: &url::Url) -> std::collections::BTreeMap<String, String> {
    url.query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

fn first_query(
    query: &std::collections::BTreeMap<String, String>,
    keys: &[&str],
) -> Option<String> {
    keys.iter().find_map(|key| query.get(*key).cloned())
}

fn query_list(query: &std::collections::BTreeMap<String, String>, key: &str) -> Vec<String> {
    query
        .get(key)
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn query_u16(query: &std::collections::BTreeMap<String, String>, key: &str) -> Option<u16> {
    query.get(key).and_then(|value| value.parse().ok())
}

fn query_u32(query: &std::collections::BTreeMap<String, String>, key: &str) -> Option<u32> {
    query.get(key).and_then(|value| value.parse().ok())
}

fn query_bool(query: &std::collections::BTreeMap<String, String>, key: &str) -> TriBool {
    query
        .get(key)
        .map(|value| TriBool::parse(value))
        .unwrap_or_default()
}

fn json_string(value: &serde_json::Value, key: &str) -> Option<String> {
    value.get(key).and_then(|value| {
        value
            .as_str()
            .map(ToOwned::to_owned)
            .or_else(|| value.as_i64().map(|n| n.to_string()))
    })
}

fn yaml_str(value: &serde_yaml::Value, path: &str) -> Option<String> {
    yaml_path(value, path).and_then(|value| {
        value
            .as_str()
            .map(ToOwned::to_owned)
            .or_else(|| value.as_i64().map(|n| n.to_string()))
            .or_else(|| value.as_bool().map(|b| b.to_string()))
    })
}

fn yaml_u16(value: &serde_yaml::Value, path: &str) -> Option<u16> {
    yaml_path(value, path).and_then(|value| {
        value
            .as_u64()
            .map(|n| n as u16)
            .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
    })
}

fn yaml_u32(value: &serde_yaml::Value, path: &str) -> Option<u32> {
    yaml_path(value, path).and_then(|value| {
        value
            .as_u64()
            .map(|n| n as u32)
            .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
    })
}

fn yaml_bool(value: &serde_yaml::Value, path: &str) -> Option<bool> {
    yaml_path(value, path).and_then(|value| {
        value.as_bool().or_else(|| {
            value
                .as_str()
                .map(|s| matches!(s.to_ascii_lowercase().as_str(), "true" | "1" | "yes"))
        })
    })
}

fn yaml_string_list(value: &serde_yaml::Value, path: &str) -> Vec<String> {
    yaml_path(value, path)
        .and_then(serde_yaml::Value::as_sequence)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    item.as_str()
                        .map(ToOwned::to_owned)
                        .or_else(|| item.as_i64().map(|n| n.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn yaml_path<'a>(value: &'a serde_yaml::Value, path: &str) -> Option<&'a serde_yaml::Value> {
    let mut current = value;
    for part in path.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

fn bool_word(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn node_names(nodes: &[Proxy]) -> String {
    nodes
        .iter()
        .map(|node| node.remark.as_str())
        .collect::<Vec<_>>()
        .join(",")
}
