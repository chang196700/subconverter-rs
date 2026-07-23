use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::model::{CronTaskConfig, ProxyGroupConfig, RegexMatchConfig, RulesetConfig, TriBool};
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    Ini,
    Toml,
    Yaml,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecuritySettings {
    pub allowed_local_roots: Vec<String>,
    pub allow_private_network: bool,
    pub allow_plain_http: bool,
    pub max_download_bytes: usize,
    pub connect_timeout_seconds: u64,
    pub request_timeout_seconds: u64,
    pub max_redirects: usize,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            allowed_local_roots: vec!["base".to_string(), "profiles".to_string()],
            allow_private_network: false,
            allow_plain_http: false,
            max_download_bytes: 1_048_576,
            connect_timeout_seconds: 10,
            request_timeout_seconds: 30,
            max_redirects: 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    pub api_mode: bool,
    pub api_access_token: String,
    pub listen: String,
    pub port: u16,
    pub managed_config_prefix: String,
    pub write_managed_config: bool,
    pub config_update_interval: u64,
    pub config_update_strict: bool,
    pub update_ruleset_on_request: bool,
    pub reload_conf_on_request: bool,
    pub skip_failed_links: bool,
    pub enable_filter: bool,
    pub filter_script: String,
    pub enable_rule_generator: bool,
    pub overwrite_original_rules: bool,
    pub default_urls: Vec<String>,
    pub enable_insert: bool,
    pub insert_urls: Vec<String>,
    pub prepend_insert_url: bool,
    pub default_external_config: String,
    pub proxy_config: String,
    pub proxy_ruleset: String,
    pub proxy_subscription: String,
    pub base_path: String,
    pub clash_rule_base: String,
    pub surge_rule_base: String,
    pub surfboard_rule_base: String,
    pub mellow_rule_base: String,
    pub quan_rule_base: String,
    pub quanx_rule_base: String,
    pub loon_rule_base: String,
    pub sssub_rule_base: String,
    pub singbox_rule_base: String,
    pub append_proxy_type: bool,
    pub append_sub_userinfo: bool,
    pub udp_flag: TriBool,
    pub tcp_fast_open_flag: TriBool,
    pub skip_cert_verify_flag: TriBool,
    pub tls13_flag: TriBool,
    pub sort_flag: bool,
    pub sort_script: String,
    pub filter_deprecated_nodes: bool,
    pub exclude_remarks: Vec<String>,
    pub include_remarks: Vec<String>,
    pub rename_node: Vec<RegexMatchConfig>,
    pub emoji: Vec<RegexMatchConfig>,
    pub add_emoji: bool,
    pub remove_old_emoji: bool,
    pub stream_rule: Vec<RegexMatchConfig>,
    pub time_rule: Vec<RegexMatchConfig>,
    pub rulesets: Vec<RulesetConfig>,
    pub custom_proxy_groups: Vec<ProxyGroupConfig>,
    pub cron_tasks: Vec<CronTaskConfig>,
    pub enable_cron: bool,
    pub cache_subscription_seconds: u64,
    pub cache_config_seconds: u64,
    pub cache_ruleset_seconds: u64,
    pub serve_cache_on_fetch_fail: bool,
    pub script_memory_limit_bytes: usize,
    pub script_timeout_millis: u64,
    pub script_clean_context: bool,
    pub template_path: String,
    pub template_vars: BTreeMap<String, String>,
    pub security: SecuritySettings,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            api_mode: true,
            api_access_token: String::new(),
            listen: "127.0.0.1".to_string(),
            port: 25500,
            managed_config_prefix: String::new(),
            write_managed_config: false,
            config_update_interval: 0,
            config_update_strict: false,
            update_ruleset_on_request: false,
            reload_conf_on_request: false,
            skip_failed_links: false,
            enable_filter: false,
            filter_script: String::new(),
            enable_rule_generator: true,
            overwrite_original_rules: true,
            default_urls: Vec::new(),
            enable_insert: false,
            insert_urls: Vec::new(),
            prepend_insert_url: true,
            default_external_config: String::new(),
            proxy_config: String::new(),
            proxy_ruleset: String::new(),
            proxy_subscription: String::new(),
            base_path: "base".to_string(),
            clash_rule_base: String::new(),
            surge_rule_base: String::new(),
            surfboard_rule_base: String::new(),
            mellow_rule_base: String::new(),
            quan_rule_base: String::new(),
            quanx_rule_base: String::new(),
            loon_rule_base: String::new(),
            sssub_rule_base: String::new(),
            singbox_rule_base: String::new(),
            append_proxy_type: false,
            append_sub_userinfo: true,
            udp_flag: TriBool::Undefined,
            tcp_fast_open_flag: TriBool::Undefined,
            skip_cert_verify_flag: TriBool::Undefined,
            tls13_flag: TriBool::Undefined,
            sort_flag: false,
            sort_script: String::new(),
            filter_deprecated_nodes: true,
            exclude_remarks: Vec::new(),
            include_remarks: Vec::new(),
            rename_node: Vec::new(),
            emoji: Vec::new(),
            add_emoji: false,
            remove_old_emoji: false,
            stream_rule: Vec::new(),
            time_rule: Vec::new(),
            rulesets: Vec::new(),
            custom_proxy_groups: Vec::new(),
            cron_tasks: Vec::new(),
            enable_cron: false,
            cache_subscription_seconds: 60,
            cache_config_seconds: 300,
            cache_ruleset_seconds: 21_600,
            serve_cache_on_fetch_fail: false,
            script_memory_limit_bytes: 16 * 1024 * 1024,
            script_timeout_millis: 1_000,
            script_clean_context: true,
            template_path: "templates".to_string(),
            template_vars: BTreeMap::new(),
            security: SecuritySettings::default(),
        }
    }
}

impl Settings {
    pub fn parse(content: &str, format: ConfigFormat) -> Result<Self> {
        match format {
            ConfigFormat::Toml => Self::parse_toml(content),
            ConfigFormat::Yaml => Self::parse_yaml(content),
            ConfigFormat::Ini => Ok(Self::parse_ini(content)),
        }
    }

    pub fn detect_and_parse(content: &str) -> Result<Self> {
        if content.contains("[[") {
            return Self::parse_toml(content);
        }
        if content.contains("[common]")
            || content.contains("[node_pref]")
            || content.contains("[managed_config]")
            || content.contains("[rulesets]")
            || content.contains("[emojis]")
            || content.contains("[userinfo]")
            || content.contains("[custom]")
            || content.contains("custom_proxy_group=")
            || content.contains("custom_proxy_group =")
            || content.contains("enable_rule_generator=")
            || content.contains("enable_rule_generator =")
            || content.contains("api_mode=")
            || content.contains("api_mode =")
        {
            return Ok(Self::parse_ini(content));
        }
        if content.contains("common:")
            || content.contains("node_pref:")
            || content.contains("rulesets:")
            || content.contains("proxy_groups:")
            || content.contains("emojis:")
            || content.contains("managed_config:")
            || content.contains("template:")
        {
            return Self::parse_yaml(content);
        }
        Self::parse_toml(content)
    }

    pub fn overlay(content: &str, base: &Self) -> Result<Self> {
        let parsed = Self::detect_and_parse(content)?;
        let mut merged = base.clone();
        macro_rules! overlay {
            ($field:ident, $($key:literal),+ $(,)?) => {
                if config_has_any_key(content, &[$($key),+]) {
                    merged.$field = parsed.$field.clone();
                }
            };
        }

        overlay!(api_mode, "api_mode");
        overlay!(api_access_token, "api_access_token");
        overlay!(listen, "listen");
        overlay!(port, "port");
        overlay!(managed_config_prefix, "managed_config_prefix");
        overlay!(write_managed_config, "write_managed_config");
        overlay!(config_update_interval, "config_update_interval");
        overlay!(config_update_strict, "config_update_strict");
        overlay!(update_ruleset_on_request, "update_ruleset_on_request");
        overlay!(reload_conf_on_request, "reload_conf_on_request");
        overlay!(skip_failed_links, "skip_failed_links");
        overlay!(enable_filter, "enable_filter");
        overlay!(filter_script, "filter_script");
        overlay!(enable_rule_generator, "enabled", "enable_rule_generator");
        overlay!(overwrite_original_rules, "overwrite_original_rules");
        overlay!(default_urls, "default_url");
        overlay!(enable_insert, "enable_insert");
        overlay!(insert_urls, "insert_url");
        overlay!(prepend_insert_url, "prepend_insert_url");
        overlay!(default_external_config, "default_external_config");
        overlay!(proxy_config, "proxy_config");
        overlay!(proxy_ruleset, "proxy_ruleset");
        overlay!(proxy_subscription, "proxy_subscription");
        overlay!(base_path, "base_path");
        overlay!(clash_rule_base, "clash_rule_base");
        overlay!(surge_rule_base, "surge_rule_base");
        overlay!(surfboard_rule_base, "surfboard_rule_base");
        overlay!(mellow_rule_base, "mellow_rule_base");
        overlay!(quan_rule_base, "quan_rule_base");
        overlay!(quanx_rule_base, "quanx_rule_base");
        overlay!(loon_rule_base, "loon_rule_base");
        overlay!(sssub_rule_base, "sssub_rule_base");
        overlay!(singbox_rule_base, "singbox_rule_base");
        overlay!(append_proxy_type, "append_proxy_type");
        overlay!(append_sub_userinfo, "append_sub_userinfo");
        overlay!(udp_flag, "udp_flag");
        overlay!(tcp_fast_open_flag, "tcp_fast_open_flag");
        overlay!(skip_cert_verify_flag, "skip_cert_verify_flag");
        overlay!(tls13_flag, "tls13_flag");
        overlay!(sort_flag, "sort_flag");
        overlay!(sort_script, "sort_script");
        overlay!(filter_deprecated_nodes, "filter_deprecated_nodes");
        if config_has_key_prefix(content, "exclude_remarks") {
            merged.exclude_remarks = parsed.exclude_remarks;
        }
        if config_has_key_prefix(content, "include_remarks") {
            merged.include_remarks = parsed.include_remarks;
        }
        if config_has_key_prefix(content, "rename_node") {
            merged.rename_node = parsed.rename_node;
        }
        if config_has_any_key(content, &["emoji", "rules"]) {
            merged.emoji = parsed.emoji;
        }
        overlay!(add_emoji, "add_emoji");
        overlay!(remove_old_emoji, "remove_old_emoji");
        if config_has_key_prefix(content, "stream_rule") {
            merged.stream_rule = parsed.stream_rule;
        }
        if config_has_key_prefix(content, "time_rule") {
            merged.time_rule = parsed.time_rule;
        }
        if config_has_any_key(content, &["ruleset", "rulesets"])
            || config_has_table(content, "rulesets.rulesets")
        {
            merged.rulesets = parsed.rulesets;
        }
        if config_has_key_prefix(content, "custom_proxy_group")
            || config_has_table(content, "custom_groups")
            || config_has_table(content, "proxy_groups")
        {
            merged.custom_proxy_groups = parsed.custom_proxy_groups;
        }
        if config_has_key_prefix(content, "task") || config_has_table(content, "tasks") {
            merged.cron_tasks = parsed.cron_tasks;
            merged.enable_cron = parsed.enable_cron;
        }
        overlay!(cache_subscription_seconds, "cache_subscription");
        overlay!(cache_config_seconds, "cache_config");
        overlay!(cache_ruleset_seconds, "cache_ruleset");
        overlay!(serve_cache_on_fetch_fail, "serve_cache_on_fetch_fail");
        overlay!(script_memory_limit_bytes, "script_memory_limit_bytes");
        overlay!(script_timeout_millis, "script_timeout_millis");
        overlay!(script_clean_context, "script_clean_context");
        overlay!(template_path, "template_path");
        if config_has_table(content, "template") {
            merged.template_vars.extend(parsed.template_vars);
        }

        if config_has_any_key(content, &["allowed_local_roots"]) {
            merged.security.allowed_local_roots = parsed.security.allowed_local_roots;
        }
        if config_has_any_key(content, &["allow_private_network"]) {
            merged.security.allow_private_network = parsed.security.allow_private_network;
        }
        if config_has_any_key(content, &["allow_plain_http"]) {
            merged.security.allow_plain_http = parsed.security.allow_plain_http;
        }
        if config_has_any_key(content, &["max_download_bytes"]) {
            merged.security.max_download_bytes = parsed.security.max_download_bytes;
        }
        if config_has_any_key(content, &["connect_timeout_seconds"]) {
            merged.security.connect_timeout_seconds = parsed.security.connect_timeout_seconds;
        }
        if config_has_any_key(content, &["request_timeout_seconds"]) {
            merged.security.request_timeout_seconds = parsed.security.request_timeout_seconds;
        }
        if config_has_any_key(content, &["max_redirects"]) {
            merged.security.max_redirects = parsed.security.max_redirects;
        }
        Ok(merged)
    }

    pub fn apply_env(&mut self, get_env: impl Fn(&str) -> Option<String>) {
        if let Some(listen) = get_env("LISTEN") {
            self.listen = listen;
        }
        if let Some(port) = get_env("PORT").and_then(|value| value.parse::<u16>().ok()) {
            self.port = port;
        }
        if let Some(api_mode) = get_env("API_MODE") {
            self.api_mode = TriBool::parse(&api_mode).get(self.api_mode);
        }
        if let Some(prefix) = get_env("MANAGED_PREFIX") {
            self.managed_config_prefix = prefix;
        }
        if let Some(token) = get_env("API_TOKEN") {
            self.api_access_token = token;
        }
        if let Some(value) = get_env("ALLOW_PRIVATE_NETWORK") {
            self.security.allow_private_network =
                TriBool::parse(&value).get(self.security.allow_private_network);
        }
        if let Some(value) = get_env("ALLOW_PLAIN_HTTP") {
            self.security.allow_plain_http =
                TriBool::parse(&value).get(self.security.allow_plain_http);
        }
    }

    fn parse_toml(content: &str) -> Result<Self> {
        let value: toml::Value =
            toml::from_str(content).map_err(|err| Error::Parse(err.to_string()))?;
        let mut settings = Self::default();
        if let Some(common) = value.get("common") {
            set_common(&mut settings, |key| common.get(key));
            if let Some(value) = common.get("enable_filter").and_then(toml_bool) {
                settings.enable_filter = value;
            }
            if let Some(value) = common.get("filter_script").and_then(toml_string) {
                settings.filter_script = value.to_string();
            }
            settings.include_remarks = toml_string_array(common, "include_remarks");
            settings.exclude_remarks = toml_string_array(common, "exclude_remarks");
            settings.default_urls = toml_string_array(common, "default_url");
            settings.insert_urls = toml_string_array(common, "insert_url");
            if let Some(value) = common.get("prepend_insert_url").and_then(toml_bool) {
                settings.prepend_insert_url = value;
            }
            if let Some(value) = common.get("append_proxy_type").and_then(toml_bool) {
                settings.append_proxy_type = value;
            }
            if let Some(value) = common.get("default_external_config").and_then(toml_string) {
                settings.default_external_config = value.to_string();
            }
        }
        set_toml_security(&mut settings, value.get("security"));
        set_toml_advanced(&mut settings, value.get("advanced"));
        if let Some(rulesets) = value.get("rulesets") {
            if let Some(value) = rulesets
                .get("enabled")
                .or_else(|| rulesets.get("enable_rule_generator"))
                .and_then(toml_bool)
            {
                settings.enable_rule_generator = value;
            }
            if let Some(value) = rulesets.get("overwrite_original_rules").and_then(toml_bool) {
                settings.overwrite_original_rules = value;
            }
        }
        if let Some(value) = value.get("enable_rule_generator").and_then(toml_bool) {
            settings.enable_rule_generator = value;
        }
        if let Some(value) = value.get("overwrite_original_rules").and_then(toml_bool) {
            settings.overwrite_original_rules = value;
        }
        set_toml_rule_bases(&mut settings, &value);
        if let Some(server) = value.get("server") {
            if let Some(listen) = server.get("listen").and_then(toml_string) {
                settings.listen = listen.to_string();
            }
            if let Some(port) = server.get("port").and_then(toml_int) {
                settings.port = port as u16;
            }
        }
        if let Some(managed) = value.get("managed_config") {
            if let Some(prefix) = managed.get("managed_config_prefix").and_then(toml_string) {
                settings.managed_config_prefix = prefix.to_string();
            }
            if let Some(write) = managed.get("write_managed_config").and_then(toml_bool) {
                settings.write_managed_config = write;
            }
            if let Some(interval) = managed.get("config_update_interval").and_then(toml_int) {
                settings.config_update_interval = interval.max(0) as u64;
            }
            if let Some(strict) = managed.get("config_update_strict").and_then(toml_bool) {
                settings.config_update_strict = strict;
            }
        }
        if let Some(node_pref) = value.get("node_pref") {
            set_node_pref(&mut settings, |key| node_pref.get(key));
            if let Some(value) = node_pref.get("sort_script").and_then(toml_string) {
                settings.sort_script = value.to_string();
            }
            if let Some(value) = node_pref.get("append_sub_userinfo").and_then(toml_bool) {
                settings.append_sub_userinfo = value;
            }
            settings.rename_node = toml_regex_array(node_pref, "rename_node", "replace");
            settings
                .include_remarks
                .extend(toml_string_array(node_pref, "include_remarks"));
            settings
                .exclude_remarks
                .extend(toml_string_array(node_pref, "exclude_remarks"));
        }
        if let Some(emojis) = value.get("emojis") {
            if let Some(value) = emojis.get("add_emoji").and_then(toml_bool) {
                settings.add_emoji = value;
            }
            if let Some(value) = emojis.get("remove_old_emoji").and_then(toml_bool) {
                settings.remove_old_emoji = value;
            }
            settings.emoji = toml_regex_array(emojis, "emoji", "emoji");
        }
        if let Some(userinfo) = value.get("userinfo") {
            settings.stream_rule = toml_regex_array(userinfo, "stream_rule", "replace");
            settings.time_rule = toml_regex_array(userinfo, "time_rule", "replace");
        }
        settings.custom_proxy_groups = toml_proxy_groups(&value);
        settings.rulesets = toml_rulesets(&value);
        settings.cron_tasks = toml_cron_tasks(&value);
        settings.enable_cron = !settings.cron_tasks.is_empty();
        if let Some(template) = value.get("template") {
            if let Some(path) = template.get("template_path").and_then(toml_string) {
                settings.template_path = path.to_string();
            }
            settings.template_vars = toml_template_vars(template);
        }
        if !settings.managed_config_prefix.is_empty() {
            settings.template_vars.insert(
                "managed_config_prefix".to_string(),
                settings.managed_config_prefix.clone(),
            );
        }
        Ok(settings)
    }

    fn parse_yaml(content: &str) -> Result<Self> {
        let value: serde_yaml::Value =
            serde_yaml::from_str(content).map_err(|err| Error::Parse(err.to_string()))?;
        let mut settings = Self::default();
        if let Some(common) = value.get("common") {
            set_common(&mut settings, |key| common.get(key));
            if let Some(value) = common.get("enable_filter").and_then(yaml_bool) {
                settings.enable_filter = value;
            }
            if let Some(value) = common.get("filter_script").and_then(yaml_string) {
                settings.filter_script = value.to_string();
            }
            settings.include_remarks = yaml_string_array(common, "include_remarks");
            settings.exclude_remarks = yaml_string_array(common, "exclude_remarks");
            settings.default_urls = yaml_string_array(common, "default_url");
            settings.insert_urls = yaml_string_array(common, "insert_url");
            if let Some(value) = common.get("prepend_insert_url").and_then(yaml_bool) {
                settings.prepend_insert_url = value;
            }
            if let Some(value) = common.get("append_proxy_type").and_then(yaml_bool) {
                settings.append_proxy_type = value;
            }
            if let Some(value) = common.get("default_external_config").and_then(yaml_string) {
                settings.default_external_config = value.to_string();
            }
        }
        set_yaml_security(&mut settings, value.get("security"));
        set_yaml_advanced(&mut settings, value.get("advanced"));
        if let Some(rulesets) = value.get("rulesets") {
            if let Some(value) = rulesets
                .get("enabled")
                .or_else(|| rulesets.get("enable_rule_generator"))
                .and_then(yaml_bool)
            {
                settings.enable_rule_generator = value;
            }
            if let Some(value) = rulesets.get("overwrite_original_rules").and_then(yaml_bool) {
                settings.overwrite_original_rules = value;
            }
        }
        if let Some(value) = value.get("enable_rule_generator").and_then(yaml_bool) {
            settings.enable_rule_generator = value;
        }
        if let Some(value) = value.get("overwrite_original_rules").and_then(yaml_bool) {
            settings.overwrite_original_rules = value;
        }
        set_yaml_rule_bases(&mut settings, &value);
        if let Some(server) = value.get("server") {
            if let Some(listen) = server.get("listen").and_then(yaml_string) {
                settings.listen = listen.to_string();
            }
            if let Some(port) = server.get("port").and_then(yaml_int) {
                settings.port = port as u16;
            }
        }
        if let Some(managed) = value.get("managed_config") {
            if let Some(prefix) = managed.get("managed_config_prefix").and_then(yaml_string) {
                settings.managed_config_prefix = prefix.to_string();
            }
            if let Some(write) = managed.get("write_managed_config").and_then(yaml_bool) {
                settings.write_managed_config = write;
            }
            if let Some(interval) = managed.get("config_update_interval").and_then(yaml_int) {
                settings.config_update_interval = interval.max(0) as u64;
            }
            if let Some(strict) = managed.get("config_update_strict").and_then(yaml_bool) {
                settings.config_update_strict = strict;
            }
        }
        if let Some(node_pref) = value.get("node_pref") {
            set_node_pref(&mut settings, |key| node_pref.get(key));
            if let Some(value) = node_pref.get("sort_script").and_then(yaml_string) {
                settings.sort_script = value.to_string();
            }
            if let Some(value) = node_pref.get("append_sub_userinfo").and_then(yaml_bool) {
                settings.append_sub_userinfo = value;
            }
            settings.rename_node = yaml_regex_array(node_pref, "rename_node", "replace");
            settings
                .include_remarks
                .extend(yaml_string_array(node_pref, "include_remarks"));
            settings
                .exclude_remarks
                .extend(yaml_string_array(node_pref, "exclude_remarks"));
        }
        if let Some(emojis) = value.get("emojis") {
            if let Some(value) = emojis.get("add_emoji").and_then(yaml_bool) {
                settings.add_emoji = value;
            }
            if let Some(value) = emojis.get("remove_old_emoji").and_then(yaml_bool) {
                settings.remove_old_emoji = value;
            }
            settings.emoji = yaml_regex_array(emojis, "emoji", "emoji");
            if settings.emoji.is_empty() {
                settings.emoji = yaml_regex_array(emojis, "rules", "emoji");
            }
        }
        if let Some(userinfo) = value.get("userinfo") {
            settings.stream_rule = yaml_regex_array(userinfo, "stream_rule", "replace");
            settings.time_rule = yaml_regex_array(userinfo, "time_rule", "replace");
        }
        settings.custom_proxy_groups = yaml_proxy_groups(&value);
        settings.rulesets = yaml_rulesets(&value);
        settings.cron_tasks = yaml_cron_tasks(&value);
        settings.enable_cron = !settings.cron_tasks.is_empty();
        if let Some(template) = value.get("template") {
            if let Some(path) = template.get("template_path").and_then(yaml_string) {
                settings.template_path = path.to_string();
            }
            settings.template_vars = yaml_template_vars(template);
        }
        if !settings.managed_config_prefix.is_empty() {
            settings.template_vars.insert(
                "managed_config_prefix".to_string(),
                settings.managed_config_prefix.clone(),
            );
        }
        Ok(settings)
    }

    fn parse_ini(content: &str) -> Self {
        let mut settings = Self::default();
        let mut section = String::new();
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
                section = line[1..line.len() - 1].to_ascii_lowercase();
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let raw_value = value.trim().trim_matches('"');
            let unescaped_value;
            let value = if is_rule_base_key(key) && raw_value.contains("\\n") {
                unescaped_value = raw_value.replace("\\r\\n", "\n").replace("\\n", "\n");
                unescaped_value.as_str()
            } else {
                raw_value
            };
            match (section.as_str(), key) {
                ("common", "api_mode") => {
                    settings.api_mode = TriBool::parse(value).get(settings.api_mode)
                }
                ("common", "api_access_token") => settings.api_access_token = value.to_string(),
                ("common", "update_ruleset_on_request") => {
                    settings.update_ruleset_on_request =
                        TriBool::parse(value).get(settings.update_ruleset_on_request)
                }
                ("common", "default_url") => {
                    settings.default_urls = split_string_list(value);
                }
                ("common", "enable_insert") => {
                    settings.enable_insert = TriBool::parse(value).get(settings.enable_insert)
                }
                ("common", "insert_url") => {
                    settings.insert_urls = value
                        .split('|')
                        .map(str::trim)
                        .filter(|item| !item.is_empty())
                        .map(ToOwned::to_owned)
                        .collect()
                }
                ("common", "prepend_insert_url") => {
                    settings.prepend_insert_url =
                        TriBool::parse(value).get(settings.prepend_insert_url)
                }
                ("common", "default_external_config") => {
                    settings.default_external_config = value.to_string()
                }
                ("common", "proxy_config") => settings.proxy_config = value.to_string(),
                ("common", "proxy_ruleset") => settings.proxy_ruleset = value.to_string(),
                ("common", "proxy_subscription") => settings.proxy_subscription = value.to_string(),
                ("common", "reload_conf_on_request") => {
                    settings.reload_conf_on_request =
                        TriBool::parse(value).get(settings.reload_conf_on_request)
                }
                ("common", "enable_filter") => {
                    settings.enable_filter = TriBool::parse(value).get(settings.enable_filter)
                }
                ("common", "filter_script") => settings.filter_script = value.to_string(),
                ("common", "base_path") | ("", "base_path") => {
                    settings.base_path = value.to_string()
                }
                ("common", "append_proxy_type") => {
                    settings.append_proxy_type =
                        TriBool::parse(value).get(settings.append_proxy_type)
                }
                ("common", "clash_rule_base")
                | ("custom", "clash_rule_base")
                | ("", "clash_rule_base") => settings.clash_rule_base = value.to_string(),
                ("common", "surge_rule_base")
                | ("custom", "surge_rule_base")
                | ("", "surge_rule_base") => settings.surge_rule_base = value.to_string(),
                ("common", "surfboard_rule_base")
                | ("custom", "surfboard_rule_base")
                | ("", "surfboard_rule_base") => settings.surfboard_rule_base = value.to_string(),
                ("common", "mellow_rule_base")
                | ("custom", "mellow_rule_base")
                | ("", "mellow_rule_base") => settings.mellow_rule_base = value.to_string(),
                ("common", "quan_rule_base")
                | ("custom", "quan_rule_base")
                | ("", "quan_rule_base") => settings.quan_rule_base = value.to_string(),
                ("common", "quanx_rule_base")
                | ("custom", "quanx_rule_base")
                | ("", "quanx_rule_base") => settings.quanx_rule_base = value.to_string(),
                ("common", "loon_rule_base")
                | ("custom", "loon_rule_base")
                | ("", "loon_rule_base") => settings.loon_rule_base = value.to_string(),
                ("common", "sssub_rule_base")
                | ("custom", "sssub_rule_base")
                | ("", "sssub_rule_base") => settings.sssub_rule_base = value.to_string(),
                ("common", "singbox_rule_base")
                | ("custom", "singbox_rule_base")
                | ("", "singbox_rule_base") => settings.singbox_rule_base = value.to_string(),
                ("managed_config", "managed_config_prefix") => {
                    settings.managed_config_prefix = value.to_string()
                }
                ("managed_config", "write_managed_config") => {
                    settings.write_managed_config =
                        TriBool::parse(value).get(settings.write_managed_config)
                }
                ("managed_config", "config_update_interval") => {
                    if let Ok(interval) = value.parse() {
                        settings.config_update_interval = interval;
                    }
                }
                ("managed_config", "config_update_strict") => {
                    settings.config_update_strict =
                        TriBool::parse(value).get(settings.config_update_strict)
                }
                ("rulesets", "enabled") | ("rulesets", "enable_rule_generator") => {
                    settings.enable_rule_generator =
                        TriBool::parse(value).get(settings.enable_rule_generator)
                }
                ("rulesets", "overwrite_original_rules")
                | ("custom", "overwrite_original_rules") => {
                    settings.overwrite_original_rules =
                        TriBool::parse(value).get(settings.overwrite_original_rules)
                }
                ("advanced", "skip_failed_links") => {
                    settings.skip_failed_links =
                        TriBool::parse(value).get(settings.skip_failed_links)
                }
                ("advanced", "cache_subscription") => {
                    if let Ok(seconds) = value.parse() {
                        settings.cache_subscription_seconds = seconds;
                    }
                }
                ("advanced", "cache_config") => {
                    if let Ok(seconds) = value.parse() {
                        settings.cache_config_seconds = seconds;
                    }
                }
                ("advanced", "cache_ruleset") => {
                    if let Ok(seconds) = value.parse() {
                        settings.cache_ruleset_seconds = seconds;
                    }
                }
                ("advanced", "serve_cache_on_fetch_fail") => {
                    settings.serve_cache_on_fetch_fail =
                        TriBool::parse(value).get(settings.serve_cache_on_fetch_fail)
                }
                ("advanced", "script_memory_limit_bytes") => {
                    if let Ok(bytes) = value.parse() {
                        settings.script_memory_limit_bytes = bytes;
                    }
                }
                ("advanced", "script_timeout_millis") => {
                    if let Ok(milliseconds) = value.parse() {
                        settings.script_timeout_millis = milliseconds;
                    }
                }
                ("advanced", "script_clean_context") => {
                    settings.script_clean_context =
                        TriBool::parse(value).get(settings.script_clean_context)
                }
                ("security", "allow_private_network") => {
                    settings.security.allow_private_network =
                        TriBool::parse(value).get(settings.security.allow_private_network)
                }
                ("security", "allow_plain_http") => {
                    settings.security.allow_plain_http =
                        TriBool::parse(value).get(settings.security.allow_plain_http)
                }
                ("security", "allowed_local_roots") => {
                    settings.security.allowed_local_roots = split_string_list(value)
                }
                ("security", "max_download_bytes") => {
                    if let Ok(bytes) = value.parse() {
                        settings.security.max_download_bytes = bytes;
                    }
                }
                ("security", "connect_timeout_seconds") => {
                    if let Ok(seconds) = value.parse() {
                        settings.security.connect_timeout_seconds = seconds;
                    }
                }
                ("security", "request_timeout_seconds") => {
                    if let Ok(seconds) = value.parse() {
                        settings.security.request_timeout_seconds = seconds;
                    }
                }
                ("security", "max_redirects") => {
                    if let Ok(redirects) = value.parse() {
                        settings.security.max_redirects = redirects;
                    }
                }
                ("tasks", _) if key.starts_with("task") => {
                    if let Some(task) = parse_ini_cron_task(value) {
                        settings.cron_tasks.push(task);
                        settings.enable_cron = true;
                    }
                }
                ("server", "listen") | ("", "listen") => settings.listen = value.to_string(),
                ("server", "port") | ("", "port") => {
                    if let Ok(port) = value.parse() {
                        settings.port = port;
                    }
                }
                _ if key.starts_with("exclude_remarks") => {
                    settings.exclude_remarks.push(value.to_string())
                }
                _ if key.starts_with("include_remarks") => {
                    settings.include_remarks.push(value.to_string())
                }
                ("node_pref", _) if key.starts_with("rename_node") => {
                    if let Some(item) = parse_regex_pair(value, "@") {
                        settings.rename_node.push(item);
                    }
                }
                ("node_pref", "append_sub_userinfo") => {
                    settings.append_sub_userinfo =
                        TriBool::parse(value).get(settings.append_sub_userinfo)
                }
                ("node_pref", "udp_flag") => settings.udp_flag = TriBool::parse(value),
                ("node_pref", "tcp_fast_open_flag") => {
                    settings.tcp_fast_open_flag = TriBool::parse(value)
                }
                ("node_pref", "skip_cert_verify_flag") => {
                    settings.skip_cert_verify_flag = TriBool::parse(value)
                }
                ("node_pref", "tls13_flag") => settings.tls13_flag = TriBool::parse(value),
                ("node_pref", "sort_flag") => {
                    settings.sort_flag = TriBool::parse(value).get(settings.sort_flag)
                }
                ("node_pref", "sort_script") => settings.sort_script = value.to_string(),
                ("node_pref", "filter_deprecated_nodes") => {
                    settings.filter_deprecated_nodes =
                        TriBool::parse(value).get(settings.filter_deprecated_nodes)
                }
                ("node_pref", _) if key.starts_with("emoji") => {
                    if let Some(item) = parse_regex_pair(value, ",") {
                        settings.emoji.push(item);
                    }
                }
                ("emojis", _) if key.starts_with("emoji") => {
                    if let Some(item) = parse_regex_pair(value, ",") {
                        settings.emoji.push(item);
                    }
                }
                ("emojis", "add_emoji") => {
                    settings.add_emoji = TriBool::parse(value).get(settings.add_emoji)
                }
                ("emojis", "remove_old_emoji") => {
                    settings.remove_old_emoji = TriBool::parse(value).get(settings.remove_old_emoji)
                }
                ("userinfo", _) if key.starts_with("stream_rule") => {
                    if let Some(item) = parse_regex_pair(value, "|") {
                        settings.stream_rule.push(item);
                    }
                }
                ("userinfo", _) if key.starts_with("time_rule") => {
                    if let Some(item) = parse_regex_pair(value, "|") {
                        settings.time_rule.push(item);
                    }
                }
                ("rulesets", _) | ("custom", _) if key.starts_with("ruleset") => {
                    if let Some(item) = parse_ini_ruleset(value) {
                        settings.rulesets.push(item);
                    }
                }
                ("rulesets", _) | ("proxy_groups", _) | ("custom", _)
                    if key.starts_with("custom_proxy_group") =>
                {
                    if let Some(item) = parse_ini_proxy_group(value) {
                        settings.custom_proxy_groups.push(item);
                    }
                }
                ("template", "template_path") => settings.template_path = value.to_string(),
                ("template", _) => {
                    settings
                        .template_vars
                        .insert(key.to_string(), value.to_string());
                }
                _ => {}
            }
        }
        if !settings.managed_config_prefix.is_empty() {
            settings.template_vars.insert(
                "managed_config_prefix".to_string(),
                settings.managed_config_prefix.clone(),
            );
        }
        settings
    }
}

fn config_has_any_key(content: &str, keys: &[&str]) -> bool {
    keys.iter().any(|key| config_has_key_prefix(content, key))
}

fn config_has_key_prefix(content: &str, expected: &str) -> bool {
    let expected = expected.to_ascii_lowercase();
    content.lines().any(|raw_line| {
        let line = raw_line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with("//")
            || line.starts_with('[')
        {
            return false;
        }
        let separator = line.find('=').or_else(|| line.find(':'));
        let Some(separator) = separator else {
            return false;
        };
        let key = line[..separator]
            .trim()
            .trim_start_matches("- {")
            .trim_matches(|ch: char| ch == '"' || ch == '\'' || ch.is_whitespace())
            .to_ascii_lowercase();
        key == expected
            || key
                .strip_prefix(&expected)
                .is_some_and(|suffix| suffix.chars().all(|ch| ch.is_ascii_digit()))
    })
}

fn config_has_table(content: &str, expected: &str) -> bool {
    let expected = expected.to_ascii_lowercase();
    content.lines().any(|line| {
        line.trim()
            .trim_matches('[')
            .trim_matches(']')
            .trim()
            .eq_ignore_ascii_case(&expected)
    })
}

fn is_rule_base_key(key: &str) -> bool {
    matches!(
        key,
        "clash_rule_base"
            | "surge_rule_base"
            | "surfboard_rule_base"
            | "mellow_rule_base"
            | "quan_rule_base"
            | "quanx_rule_base"
            | "loon_rule_base"
            | "sssub_rule_base"
            | "singbox_rule_base"
    )
}

pub fn expand_imports_with(
    content: &str,
    mut resolver: impl FnMut(&str) -> Result<String>,
) -> Result<String> {
    let lines = content.lines().collect::<Vec<_>>();
    let mut expanded = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        let trimmed = line.trim();
        if trimmed.starts_with("[[") {
            let start = index;
            index += 1;
            while index < lines.len() && !lines[index].trim_start().starts_with('[') {
                index += 1;
            }
            let block = &lines[start..index];
            if let Some(import) = block.iter().find_map(|line| toml_import_ref(line)) {
                expanded.extend(resolver(&import)?.lines().map(ToOwned::to_owned));
            } else {
                expanded.extend(block.iter().map(|line| (*line).to_string()));
            }
            continue;
        }
        if let Some((indent, import)) = yaml_import_ref(line) {
            let imported = resolver(&import)?;
            expanded.extend(expand_yaml_import(&expanded, &indent, &imported));
        } else if let Some((prefix, import)) = ini_import_ref(line) {
            for imported in resolver(&import)?.lines() {
                let imported = imported.trim();
                if imported.is_empty() || imported.starts_with(';') || imported.starts_with('#') {
                    continue;
                }
                expanded.push(format!("{prefix}={imported}"));
            }
        } else {
            expanded.push(line.to_string());
        }
        index += 1;
    }
    Ok(expanded.join("\n"))
}

pub fn import_refs(content: &str) -> Vec<String> {
    let mut refs = Vec::new();
    let lines = content.lines().collect::<Vec<_>>();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        if line.trim().starts_with("[[") {
            let start = index;
            index += 1;
            while index < lines.len() && !lines[index].trim_start().starts_with('[') {
                index += 1;
            }
            refs.extend(
                lines[start..index]
                    .iter()
                    .filter_map(|line| toml_import_ref(line)),
            );
            continue;
        }
        if let Some((_, import)) = yaml_import_ref(line) {
            refs.push(import);
        } else if let Some((_, import)) = ini_import_ref(line) {
            refs.push(import);
        }
        index += 1;
    }
    refs.sort();
    refs.dedup();
    refs
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum YamlImportContext {
    RenameNode,
    Emoji,
    Ruleset,
    ProxyGroup,
    Unknown,
}

fn yaml_import_ref(line: &str) -> Option<(String, String)> {
    let indent_len = line.len().saturating_sub(line.trim_start().len());
    let indent = line[..indent_len].to_string();
    let trimmed = line.trim();
    let import = if let Some(inner) = trimmed
        .strip_prefix("- {")
        .and_then(|value| value.strip_suffix('}'))
    {
        inner
            .split(',')
            .find_map(|part| part.trim().strip_prefix("import:"))
    } else {
        trimmed.strip_prefix("- import:")
    }?;
    let import = trim_import_ref(import);
    if import.is_empty() {
        return None;
    }
    Some((indent, import.to_string()))
}

fn expand_yaml_import(previous_lines: &[String], indent: &str, imported: &str) -> Vec<String> {
    let context = yaml_import_context(previous_lines);
    let mut lines = Vec::new();
    for raw_line in imported.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        match context {
            YamlImportContext::RenameNode => {
                if let Some(item) = parse_regex_pair(line, "@") {
                    lines.push(format!(
                        "{indent}- {{match: {}, replace: {}}}",
                        yaml_quote(&item.r#match),
                        yaml_quote(&item.replace)
                    ));
                }
            }
            YamlImportContext::Emoji => {
                if let Some(item) = parse_regex_pair(line, ",") {
                    lines.push(format!(
                        "{indent}- {{match: {}, emoji: {}}}",
                        yaml_quote(&item.r#match),
                        yaml_quote(&item.replace)
                    ));
                }
            }
            YamlImportContext::Ruleset => {
                if let Some(item) = parse_ini_ruleset(line) {
                    let mut fields = format!(
                        "group: {}, ruleset: {}",
                        yaml_quote(&item.group),
                        yaml_quote(&item.url)
                    );
                    if item.interval != 86400 {
                        fields.push_str(&format!(", interval: {}", item.interval));
                    }
                    lines.push(format!("{indent}- {{{fields}}}"));
                }
            }
            YamlImportContext::ProxyGroup => {
                if let Some(item) = parse_ini_proxy_group(line) {
                    lines.push(format!("{indent}- name: {}", yaml_quote(&item.name)));
                    lines.push(format!("{indent}  type: {}", yaml_quote(&item.group_type)));
                    if !item.proxies.is_empty() {
                        lines.push(format!("{indent}  rule:"));
                        for proxy in item.proxies {
                            lines.push(format!("{indent}  - {}", yaml_quote(&proxy)));
                        }
                    }
                    if !item.url.is_empty() {
                        lines.push(format!("{indent}  url: {}", yaml_quote(&item.url)));
                    }
                    if item.interval > 0 {
                        lines.push(format!("{indent}  interval: {}", item.interval));
                    }
                    if item.timeout > 0 {
                        lines.push(format!("{indent}  timeout: {}", item.timeout));
                    }
                    if item.tolerance > 0 {
                        lines.push(format!("{indent}  tolerance: {}", item.tolerance));
                    }
                }
            }
            YamlImportContext::Unknown => lines.push(format!("{indent}- {}", yaml_quote(line))),
        }
    }
    lines
}

fn yaml_import_context(previous_lines: &[String]) -> YamlImportContext {
    let mut in_emojis = false;
    for line in previous_lines.iter().rev() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match trimmed {
            "custom_proxy_group:" | "custom_groups:" => return YamlImportContext::ProxyGroup,
            "rename_node:" => return YamlImportContext::RenameNode,
            "rulesets:" => return YamlImportContext::Ruleset,
            "emojis:" => in_emojis = true,
            "rules:" if in_emojis => return YamlImportContext::Emoji,
            "rules:" => {
                if previous_lines
                    .iter()
                    .rev()
                    .skip_while(|candidate| candidate.trim() != "rules:")
                    .any(|candidate| candidate.trim() == "emojis:")
                {
                    return YamlImportContext::Emoji;
                }
            }
            _ => {}
        }
    }
    YamlImportContext::Unknown
}

fn yaml_quote(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
}

fn ini_import_ref(line: &str) -> Option<(String, String)> {
    let (key, value) = line.split_once('=')?;
    let import = value.trim().strip_prefix("!!import:")?.trim();
    if import.is_empty() {
        return None;
    }
    Some((key.trim().to_string(), trim_import_ref(import).to_string()))
}

fn toml_import_ref(line: &str) -> Option<String> {
    let (key, value) = line.split_once('=')?;
    if key.trim() != "import" {
        return None;
    }
    let value = trim_import_ref(value.trim());
    if value.is_empty() {
        return None;
    }
    Some(value.to_string())
}

fn trim_import_ref(value: &str) -> &str {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_end_matches(',')
        .trim()
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    #[test]
    fn expands_ini_import_values_with_original_key() {
        let content = "[rulesets]\nruleset=!!import:snippets/rulesets.txt\n";
        let expanded = expand_imports_with(content, |path| {
            assert_eq!(path, "snippets/rulesets.txt");
            Ok("DIRECT,[]GEOIP,CN\nProxy,[]FINAL\n".to_string())
        })
        .expect("import should expand");

        assert!(expanded.contains("ruleset=DIRECT,[]GEOIP,CN"));
        assert!(expanded.contains("ruleset=Proxy,[]FINAL"));
    }

    #[test]
    fn expands_toml_import_blocks_with_imported_content() {
        let content = r#"
[[rulesets]]
import = "snippets/rulesets.toml"
"#;
        let expanded = expand_imports_with(content, |path| {
            assert_eq!(path, "snippets/rulesets.toml");
            Ok(r#"[[rulesets]]
group = "DIRECT"
ruleset = "[]GEOIP,CN"
"#
            .to_string())
        })
        .expect("import should expand");

        let settings = Settings::parse(&expanded, ConfigFormat::Toml).expect("toml should parse");
        assert_eq!(settings.rulesets.len(), 1);
        assert_eq!(settings.rulesets[0].group, "DIRECT");
    }

    #[test]
    fn expands_yaml_ruleset_import_items() {
        let content = r#"
rulesets:
  rulesets:
  - {import: snippets/rulesets.txt}
"#;
        let expanded = expand_imports_with(content, |path| {
            assert_eq!(path, "snippets/rulesets.txt");
            Ok("DIRECT,[]GEOIP,CN\nProxy,[]FINAL\n".to_string())
        })
        .expect("import should expand");
        let settings = Settings::detect_and_parse(&expanded).expect("yaml should parse");

        assert_eq!(settings.rulesets.len(), 2);
        assert_eq!(settings.rulesets[0].group, "DIRECT");
        assert_eq!(settings.rulesets[1].url, "[]FINAL");
    }

    #[test]
    fn expands_yaml_proxy_group_import_items() {
        let content = r#"
proxy_groups:
  custom_proxy_group:
  - {import: snippets/groups.txt}
"#;
        let expanded = expand_imports_with(content, |path| {
            assert_eq!(path, "snippets/groups.txt");
            Ok("Proxy`select`.*`[]DIRECT\nAuto`url-test`.*`http://www.gstatic.com/generate_204`300\n".to_string())
        })
        .expect("import should expand");
        let settings = Settings::detect_and_parse(&expanded).expect("yaml should parse");

        assert_eq!(settings.custom_proxy_groups.len(), 2);
        assert_eq!(settings.custom_proxy_groups[0].name, "Proxy");
        assert_eq!(settings.custom_proxy_groups[1].group_type, "url-test");
        assert_eq!(settings.custom_proxy_groups[1].interval, 300);
    }

    #[test]
    fn environment_variables_override_runtime_settings() {
        let mut settings = Settings {
            api_mode: false,
            api_access_token: "pref-token".to_string(),
            port: 25500,
            managed_config_prefix: "https://pref.example.test".to_string(),
            ..Settings::default()
        };
        let env = BTreeMap::from([
            ("LISTEN", "0.0.0.0"),
            ("PORT", "45678"),
            ("API_MODE", "true"),
            ("MANAGED_PREFIX", "https://env.example.test"),
            ("API_TOKEN", "env-token"),
        ]);

        settings.apply_env(|key| env.get(key).map(|value| (*value).to_string()));

        assert_eq!(settings.listen, "0.0.0.0");
        assert_eq!(settings.port, 45678);
        assert!(settings.api_mode);
        assert_eq!(settings.managed_config_prefix, "https://env.example.test");
        assert_eq!(settings.api_access_token, "env-token");
    }

    #[test]
    fn managed_config_update_defaults_parse_in_all_formats() {
        let ini = Settings::detect_and_parse(
            "[managed_config]\nconfig_update_interval=3600\nconfig_update_strict=true\n",
        )
        .expect("ini should parse");
        assert_eq!(ini.config_update_interval, 3600);
        assert!(ini.config_update_strict);

        let toml = Settings::detect_and_parse(
            "[managed_config]\nconfig_update_interval = 7200\nconfig_update_strict = true\n",
        )
        .expect("toml should parse");
        assert_eq!(toml.config_update_interval, 7200);
        assert!(toml.config_update_strict);

        let yaml = Settings::detect_and_parse(
            "managed_config:\n  config_update_interval: 1800\n  config_update_strict: true\n",
        )
        .expect("yaml should parse");
        assert_eq!(yaml.config_update_interval, 1800);
        assert!(yaml.config_update_strict);
    }

    #[test]
    fn default_external_config_parses_in_all_formats() {
        let ini =
            Settings::detect_and_parse("[common]\ndefault_external_config=config/default.ini\n")
                .expect("ini should parse");
        assert_eq!(ini.default_external_config, "config/default.ini");

        let toml = Settings::detect_and_parse(
            "[common]\ndefault_external_config = \"config/default.toml\"\n",
        )
        .expect("toml should parse");
        assert_eq!(toml.default_external_config, "config/default.toml");

        let yaml =
            Settings::detect_and_parse("common:\n  default_external_config: config/default.yml\n")
                .expect("yaml should parse");
        assert_eq!(yaml.default_external_config, "config/default.yml");
    }

    #[test]
    fn target_rule_base_paths_parse_in_all_formats() {
        let ini = Settings::detect_and_parse(
            "[common]\nbase_path=base\nclash_rule_base=base/clash.yml\nsurge_rule_base=base/surge.conf\nsurfboard_rule_base=base/surfboard.conf\nmellow_rule_base=base/mellow.conf\nquan_rule_base=base/quan.conf\nquanx_rule_base=base/quanx.conf\nloon_rule_base=base/loon.conf\nsssub_rule_base=base/sssub.conf\nsingbox_rule_base=base/singbox.json\n",
        )
        .expect("ini should parse");
        assert_eq!(ini.base_path, "base");
        assert_eq!(ini.clash_rule_base, "base/clash.yml");
        assert_eq!(ini.surge_rule_base, "base/surge.conf");
        assert_eq!(ini.surfboard_rule_base, "base/surfboard.conf");
        assert_eq!(ini.mellow_rule_base, "base/mellow.conf");
        assert_eq!(ini.quan_rule_base, "base/quan.conf");
        assert_eq!(ini.quanx_rule_base, "base/quanx.conf");
        assert_eq!(ini.loon_rule_base, "base/loon.conf");
        assert_eq!(ini.sssub_rule_base, "base/sssub.conf");
        assert_eq!(ini.singbox_rule_base, "base/singbox.json");

        let toml = Settings::detect_and_parse(
            "clash_rule_base = \"root-clash.yml\"\n[common]\nbase_path = \"base\"\nsurge_rule_base = \"base/surge.conf\"\nsingbox_rule_base = \"base/singbox.json\"\n",
        )
        .expect("toml should parse");
        assert_eq!(toml.base_path, "base");
        assert_eq!(toml.clash_rule_base, "root-clash.yml");
        assert_eq!(toml.surge_rule_base, "base/surge.conf");
        assert_eq!(toml.singbox_rule_base, "base/singbox.json");

        let yaml = Settings::detect_and_parse(
            "clash_rule_base: root-clash.yml\ncommon:\n  base_path: base\n  quanx_rule_base: base/quanx.conf\n  loon_rule_base: base/loon.conf\n",
        )
        .expect("yaml should parse");
        assert_eq!(yaml.base_path, "base");
        assert_eq!(yaml.clash_rule_base, "root-clash.yml");
        assert_eq!(yaml.quanx_rule_base, "base/quanx.conf");
        assert_eq!(yaml.loon_rule_base, "base/loon.conf");
    }

    #[test]
    fn secure_defaults_match_the_public_deployment_contract() {
        let settings = Settings::default();
        assert!(settings.api_mode);
        assert_eq!(settings.listen, "127.0.0.1");
        assert!(settings.api_access_token.is_empty());
        assert_eq!(
            settings.security.allowed_local_roots,
            ["base".to_string(), "profiles".to_string()]
        );
        assert!(!settings.security.allow_private_network);
        assert!(!settings.security.allow_plain_http);
        assert_eq!(settings.security.max_download_bytes, 1_048_576);
        assert_eq!(settings.security.connect_timeout_seconds, 10);
        assert_eq!(settings.security.request_timeout_seconds, 30);
        assert_eq!(settings.security.max_redirects, 5);
        assert_eq!(settings.script_memory_limit_bytes, 16 * 1024 * 1024);
        assert_eq!(settings.script_timeout_millis, 1_000);
    }

    #[test]
    fn overlays_preserve_omitted_values_and_apply_explicit_false_in_all_formats() {
        let base = Settings {
            api_access_token: "pref-token".to_string(),
            write_managed_config: true,
            append_sub_userinfo: true,
            security: SecuritySettings {
                allow_private_network: true,
                ..SecuritySettings::default()
            },
            rulesets: vec![RulesetConfig {
                group: "Base".to_string(),
                url: "[]FINAL".to_string(),
                interval: 60,
            }],
            ..Settings::default()
        };
        let configs = [
            r#"
[managed_config]
write_managed_config=false
[node_pref]
append_sub_userinfo=false
[security]
allow_private_network=false
[rulesets]
ruleset=DIRECT,[]FINAL
"#,
            r#"
[managed_config]
write_managed_config = false
[node_pref]
append_sub_userinfo = false
[security]
allow_private_network = false
[[rulesets]]
group = "DIRECT"
ruleset = "[]FINAL"
"#,
            r#"
managed_config:
  write_managed_config: false
node_pref:
  append_sub_userinfo: false
security:
  allow_private_network: false
rulesets:
  rulesets:
  - group: DIRECT
    ruleset: "[]FINAL"
"#,
        ];

        for config in configs {
            let merged = Settings::overlay(config, &base).expect("overlay should parse");
            assert_eq!(merged.api_access_token, "pref-token");
            assert!(!merged.write_managed_config);
            assert!(!merged.append_sub_userinfo);
            assert!(!merged.security.allow_private_network);
            assert_eq!(merged.rulesets.len(), 1);
            assert_eq!(merged.rulesets[0].group, "DIRECT");
        }
    }
}

fn set_common<'a, F, V>(settings: &mut Settings, get: F)
where
    F: Fn(&str) -> Option<&'a V>,
    V: CommonValue + 'a,
{
    if let Some(value) = get("api_mode").and_then(CommonValue::as_bool) {
        settings.api_mode = value;
    }
    if let Some(value) = get("api_access_token").and_then(CommonValue::as_str) {
        settings.api_access_token = value.to_string();
    }
    if let Some(value) = get("update_ruleset_on_request").and_then(CommonValue::as_bool) {
        settings.update_ruleset_on_request = value;
    }
    if let Some(value) = get("enable_insert").and_then(CommonValue::as_bool) {
        settings.enable_insert = value;
    }
    if let Some(value) = get("proxy_config").and_then(CommonValue::as_str) {
        settings.proxy_config = value.to_string();
    }
    if let Some(value) = get("proxy_ruleset").and_then(CommonValue::as_str) {
        settings.proxy_ruleset = value.to_string();
    }
    if let Some(value) = get("proxy_subscription").and_then(CommonValue::as_str) {
        settings.proxy_subscription = value.to_string();
    }
    if let Some(value) = get("reload_conf_on_request").and_then(CommonValue::as_bool) {
        settings.reload_conf_on_request = value;
    }
}

fn set_toml_security(settings: &mut Settings, section: Option<&toml::Value>) {
    let Some(section) = section else {
        return;
    };
    if let Some(value) = section.get("allow_private_network").and_then(toml_bool) {
        settings.security.allow_private_network = value;
    }
    if let Some(value) = section.get("allow_plain_http").and_then(toml_bool) {
        settings.security.allow_plain_http = value;
    }
    let roots = toml_string_array(section, "allowed_local_roots");
    if !roots.is_empty() {
        settings.security.allowed_local_roots = roots;
    }
    if let Some(value) = section.get("max_download_bytes").and_then(toml_int) {
        settings.security.max_download_bytes = value.max(1) as usize;
    }
    if let Some(value) = section.get("connect_timeout_seconds").and_then(toml_int) {
        settings.security.connect_timeout_seconds = value.max(1) as u64;
    }
    if let Some(value) = section.get("request_timeout_seconds").and_then(toml_int) {
        settings.security.request_timeout_seconds = value.max(1) as u64;
    }
    if let Some(value) = section.get("max_redirects").and_then(toml_int) {
        settings.security.max_redirects = value.max(0) as usize;
    }
}

fn set_yaml_security(settings: &mut Settings, section: Option<&serde_yaml::Value>) {
    let Some(section) = section else {
        return;
    };
    if let Some(value) = section.get("allow_private_network").and_then(yaml_bool) {
        settings.security.allow_private_network = value;
    }
    if let Some(value) = section.get("allow_plain_http").and_then(yaml_bool) {
        settings.security.allow_plain_http = value;
    }
    let roots = yaml_string_array(section, "allowed_local_roots");
    if !roots.is_empty() {
        settings.security.allowed_local_roots = roots;
    }
    if let Some(value) = section.get("max_download_bytes").and_then(yaml_int) {
        settings.security.max_download_bytes = value.max(1) as usize;
    }
    if let Some(value) = section.get("connect_timeout_seconds").and_then(yaml_int) {
        settings.security.connect_timeout_seconds = value.max(1) as u64;
    }
    if let Some(value) = section.get("request_timeout_seconds").and_then(yaml_int) {
        settings.security.request_timeout_seconds = value.max(1) as u64;
    }
    if let Some(value) = section.get("max_redirects").and_then(yaml_int) {
        settings.security.max_redirects = value.max(0) as usize;
    }
}

fn set_toml_advanced(settings: &mut Settings, section: Option<&toml::Value>) {
    let Some(section) = section else {
        return;
    };
    if let Some(value) = section.get("skip_failed_links").and_then(toml_bool) {
        settings.skip_failed_links = value;
    }
    if let Some(value) = section.get("cache_subscription").and_then(toml_int) {
        settings.cache_subscription_seconds = value.max(0) as u64;
    }
    if let Some(value) = section.get("cache_config").and_then(toml_int) {
        settings.cache_config_seconds = value.max(0) as u64;
    }
    if let Some(value) = section.get("cache_ruleset").and_then(toml_int) {
        settings.cache_ruleset_seconds = value.max(0) as u64;
    }
    if let Some(value) = section.get("serve_cache_on_fetch_fail").and_then(toml_bool) {
        settings.serve_cache_on_fetch_fail = value;
    }
    if let Some(value) = section.get("script_memory_limit_bytes").and_then(toml_int) {
        settings.script_memory_limit_bytes = value.max(0) as usize;
    }
    if let Some(value) = section.get("script_timeout_millis").and_then(toml_int) {
        settings.script_timeout_millis = value.max(0) as u64;
    }
    if let Some(value) = section.get("script_clean_context").and_then(toml_bool) {
        settings.script_clean_context = value;
    }
}

fn set_yaml_advanced(settings: &mut Settings, section: Option<&serde_yaml::Value>) {
    let Some(section) = section else {
        return;
    };
    if let Some(value) = section.get("skip_failed_links").and_then(yaml_bool) {
        settings.skip_failed_links = value;
    }
    if let Some(value) = section.get("cache_subscription").and_then(yaml_int) {
        settings.cache_subscription_seconds = value.max(0) as u64;
    }
    if let Some(value) = section.get("cache_config").and_then(yaml_int) {
        settings.cache_config_seconds = value.max(0) as u64;
    }
    if let Some(value) = section.get("cache_ruleset").and_then(yaml_int) {
        settings.cache_ruleset_seconds = value.max(0) as u64;
    }
    if let Some(value) = section.get("serve_cache_on_fetch_fail").and_then(yaml_bool) {
        settings.serve_cache_on_fetch_fail = value;
    }
    if let Some(value) = section.get("script_memory_limit_bytes").and_then(yaml_int) {
        settings.script_memory_limit_bytes = value.max(0) as usize;
    }
    if let Some(value) = section.get("script_timeout_millis").and_then(yaml_int) {
        settings.script_timeout_millis = value.max(0) as u64;
    }
    if let Some(value) = section.get("script_clean_context").and_then(yaml_bool) {
        settings.script_clean_context = value;
    }
}

fn set_toml_rule_bases(settings: &mut Settings, value: &toml::Value) {
    let common = value.get("common");
    set_rule_base_field(settings, |key| {
        common
            .and_then(|common| common.get(key))
            .or_else(|| value.get(key))
            .and_then(toml_string)
    });
}

fn set_yaml_rule_bases(settings: &mut Settings, value: &serde_yaml::Value) {
    let common = value.get("common");
    set_rule_base_field(settings, |key| {
        common
            .and_then(|common| common.get(key))
            .or_else(|| value.get(key))
            .and_then(yaml_string)
    });
}

fn set_rule_base_field<'a, F>(settings: &mut Settings, get: F)
where
    F: Fn(&str) -> Option<&'a str>,
{
    if let Some(value) = get("base_path") {
        settings.base_path = value.to_string();
    }
    if let Some(value) = get("clash_rule_base") {
        settings.clash_rule_base = value.to_string();
    }
    if let Some(value) = get("surge_rule_base") {
        settings.surge_rule_base = value.to_string();
    }
    if let Some(value) = get("surfboard_rule_base") {
        settings.surfboard_rule_base = value.to_string();
    }
    if let Some(value) = get("mellow_rule_base") {
        settings.mellow_rule_base = value.to_string();
    }
    if let Some(value) = get("quan_rule_base") {
        settings.quan_rule_base = value.to_string();
    }
    if let Some(value) = get("quanx_rule_base") {
        settings.quanx_rule_base = value.to_string();
    }
    if let Some(value) = get("loon_rule_base") {
        settings.loon_rule_base = value.to_string();
    }
    if let Some(value) = get("sssub_rule_base") {
        settings.sssub_rule_base = value.to_string();
    }
    if let Some(value) = get("singbox_rule_base") {
        settings.singbox_rule_base = value.to_string();
    }
}

fn set_node_pref<'a, F, V>(settings: &mut Settings, get: F)
where
    F: Fn(&str) -> Option<&'a V>,
    V: CommonValue + 'a,
{
    if let Some(value) = get("udp_flag").and_then(CommonValue::as_tribool) {
        settings.udp_flag = value;
    }
    if let Some(value) = get("tcp_fast_open_flag").and_then(CommonValue::as_tribool) {
        settings.tcp_fast_open_flag = value;
    }
    if let Some(value) = get("skip_cert_verify_flag").and_then(CommonValue::as_tribool) {
        settings.skip_cert_verify_flag = value;
    }
    if let Some(value) = get("tls13_flag").and_then(CommonValue::as_tribool) {
        settings.tls13_flag = value;
    }
    if let Some(value) = get("sort_flag").and_then(CommonValue::as_bool) {
        settings.sort_flag = value;
    }
    if let Some(value) = get("filter_deprecated_nodes").and_then(CommonValue::as_bool) {
        settings.filter_deprecated_nodes = value;
    }
}

trait CommonValue {
    fn as_bool(&self) -> Option<bool>;
    fn as_str(&self) -> Option<&str>;
    fn as_tribool(&self) -> Option<TriBool> {
        if let Some(value) = self.as_bool() {
            return Some(if value { TriBool::True } else { TriBool::False });
        }
        self.as_str().map(TriBool::parse)
    }
}

impl CommonValue for toml::Value {
    fn as_bool(&self) -> Option<bool> {
        toml_bool(self)
    }

    fn as_str(&self) -> Option<&str> {
        toml_string(self)
    }
}

impl CommonValue for serde_yaml::Value {
    fn as_bool(&self) -> Option<bool> {
        yaml_bool(self)
    }

    fn as_str(&self) -> Option<&str> {
        yaml_string(self)
    }
}

fn toml_bool(value: &toml::Value) -> Option<bool> {
    value.as_bool()
}

fn toml_string(value: &toml::Value) -> Option<&str> {
    value.as_str()
}

fn toml_int(value: &toml::Value) -> Option<i64> {
    value.as_integer()
}

fn yaml_bool(value: &serde_yaml::Value) -> Option<bool> {
    value.as_bool()
}

fn yaml_string(value: &serde_yaml::Value) -> Option<&str> {
    value.as_str()
}

fn yaml_int(value: &serde_yaml::Value) -> Option<i64> {
    value.as_i64()
}

fn toml_regex_array(root: &toml::Value, key: &str, replace_key: &str) -> Vec<RegexMatchConfig> {
    root.get(key)
        .and_then(toml::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    if let Some(script) = item.get("script").and_then(toml_string) {
                        return Some(RegexMatchConfig {
                            script: Some(script.to_string()),
                            ..RegexMatchConfig::default()
                        });
                    }
                    Some(RegexMatchConfig {
                        script: None,
                        r#match: item.get("match").and_then(toml_string)?.to_string(),
                        replace: item
                            .get(replace_key)
                            .or_else(|| item.get("replace"))
                            .and_then(toml_string)?
                            .to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn yaml_regex_array(
    root: &serde_yaml::Value,
    key: &str,
    replace_key: &str,
) -> Vec<RegexMatchConfig> {
    root.get(key)
        .and_then(serde_yaml::Value::as_sequence)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    if let Some(script) = item.get("script").and_then(yaml_string) {
                        return Some(RegexMatchConfig {
                            script: Some(script.to_string()),
                            ..RegexMatchConfig::default()
                        });
                    }
                    Some(RegexMatchConfig {
                        script: None,
                        r#match: item.get("match").and_then(yaml_string)?.to_string(),
                        replace: item
                            .get(replace_key)
                            .or_else(|| item.get("replace"))
                            .and_then(yaml_string)?
                            .to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn toml_string_array(root: &toml::Value, key: &str) -> Vec<String> {
    let Some(value) = root.get(key) else {
        return Vec::new();
    };
    if let Some(string) = toml_string(value) {
        return split_string_list(string);
    }
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(toml_string)
                .flat_map(split_string_list)
                .collect()
        })
        .unwrap_or_default()
}

fn yaml_string_array(root: &serde_yaml::Value, key: &str) -> Vec<String> {
    let Some(value) = root.get(key) else {
        return Vec::new();
    };
    if let Some(string) = yaml_string(value) {
        return split_string_list(string);
    }
    value
        .as_sequence()
        .map(|items| {
            items
                .iter()
                .filter_map(yaml_string)
                .flat_map(split_string_list)
                .collect()
        })
        .unwrap_or_default()
}

fn split_string_list(value: &str) -> Vec<String> {
    value
        .split('|')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_regex_pair(value: &str, delimiter: &str) -> Option<RegexMatchConfig> {
    let (r#match, replace) = value.split_once(delimiter)?;
    Some(RegexMatchConfig {
        script: None,
        r#match: r#match.trim().to_string(),
        replace: replace.trim().to_string(),
    })
}

fn toml_proxy_groups(root: &toml::Value) -> Vec<ProxyGroupConfig> {
    root.get("custom_groups")
        .and_then(toml::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    if item.get("import").is_some() {
                        return None;
                    }
                    Some(ProxyGroupConfig {
                        name: item.get("name").and_then(toml_string)?.to_string(),
                        group_type: item
                            .get("type")
                            .and_then(toml_string)
                            .unwrap_or("select")
                            .to_string(),
                        url: item
                            .get("url")
                            .and_then(toml_string)
                            .unwrap_or("")
                            .to_string(),
                        interval: item.get("interval").and_then(toml_int).unwrap_or(0) as i32,
                        timeout: item.get("timeout").and_then(toml_int).unwrap_or(0) as i32,
                        tolerance: item.get("tolerance").and_then(toml_int).unwrap_or(0) as i32,
                        proxies: toml_string_array(item, "rule"),
                        providers: toml_string_array(item, "use"),
                        disable_udp: item
                            .get("disable_udp")
                            .or_else(|| item.get("disable-udp"))
                            .and_then(toml_bool)
                            .map(|value| if value { TriBool::True } else { TriBool::False })
                            .unwrap_or_default(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn yaml_proxy_groups(root: &serde_yaml::Value) -> Vec<ProxyGroupConfig> {
    root.get("proxy_groups")
        .and_then(|value| {
            value
                .get("custom_proxy_group")
                .or_else(|| value.get("custom_groups"))
        })
        .or_else(|| root.get("custom_groups"))
        .and_then(serde_yaml::Value::as_sequence)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    if item.get("import").is_some() {
                        return None;
                    }
                    Some(ProxyGroupConfig {
                        name: item.get("name").and_then(yaml_string)?.to_string(),
                        group_type: item
                            .get("type")
                            .and_then(yaml_string)
                            .unwrap_or("select")
                            .to_string(),
                        url: item
                            .get("url")
                            .and_then(yaml_string)
                            .unwrap_or("")
                            .to_string(),
                        interval: item.get("interval").and_then(yaml_int).unwrap_or(0) as i32,
                        timeout: item.get("timeout").and_then(yaml_int).unwrap_or(0) as i32,
                        tolerance: item.get("tolerance").and_then(yaml_int).unwrap_or(0) as i32,
                        proxies: yaml_string_array(item, "rule"),
                        providers: yaml_string_array(item, "use"),
                        disable_udp: item
                            .get("disable_udp")
                            .or_else(|| item.get("disable-udp"))
                            .and_then(yaml_bool)
                            .map(|value| if value { TriBool::True } else { TriBool::False })
                            .unwrap_or_default(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn toml_rulesets(root: &toml::Value) -> Vec<RulesetConfig> {
    root.get("rulesets")
        .and_then(toml::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    if item.get("import").is_some() {
                        return None;
                    }
                    let group = item.get("group").and_then(toml_string)?.to_string();
                    let rule = item.get("ruleset").and_then(toml_string)?.to_string();
                    let prefix = match item.get("type").and_then(toml_string).unwrap_or("") {
                        "quantumultx" => "quanx:",
                        "clash-domain" => "clash-domain:",
                        "clash-ipcidr" => "clash-ipcidr:",
                        "clash-classic" => "clash-classic:",
                        "surge-ruleset" | "" => "",
                        _ => "",
                    };
                    Some(RulesetConfig {
                        group,
                        url: format!("{prefix}{rule}"),
                        interval: item.get("interval").and_then(toml_int).unwrap_or(86400) as i32,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn yaml_rulesets(root: &serde_yaml::Value) -> Vec<RulesetConfig> {
    root.get("rulesets")
        .and_then(|value| value.get("rulesets").or(Some(value)))
        .and_then(serde_yaml::Value::as_sequence)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    if item.get("import").is_some() {
                        return None;
                    }
                    Some(RulesetConfig {
                        group: item.get("group").and_then(yaml_string)?.to_string(),
                        url: item.get("ruleset").and_then(yaml_string)?.to_string(),
                        interval: item.get("interval").and_then(yaml_int).unwrap_or(86400) as i32,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_ini_ruleset(value: &str) -> Option<RulesetConfig> {
    if value.starts_with("!!import:") {
        return None;
    }
    let parts = value.split(',').map(str::trim).collect::<Vec<_>>();
    if parts.len() < 2 {
        return None;
    }
    let group = parts[0].to_string();
    let mut url = parts[1].to_string();
    let mut interval = 86400;
    if url.starts_with("[]") {
        if parts.len() > 2 {
            url = format!("{url},{}", parts[2]);
        }
        if parts.len() > 3 {
            interval = parts[3].parse().unwrap_or(interval);
        }
    } else if parts.len() > 2 {
        interval = parts[2].parse().unwrap_or(interval);
    }
    Some(RulesetConfig {
        group,
        url,
        interval,
    })
}

fn parse_ini_proxy_group(value: &str) -> Option<ProxyGroupConfig> {
    if value.starts_with("!!import:") {
        return None;
    }
    let parts = value.split('`').map(str::trim).collect::<Vec<_>>();
    if parts.len() < 3 {
        return None;
    }
    let mut group = ProxyGroupConfig {
        name: parts[0].to_string(),
        group_type: parts[1].to_string(),
        proxies: parts[2..].iter().map(|value| value.to_string()).collect(),
        ..ProxyGroupConfig::default()
    };
    if matches!(
        group.group_type.as_str(),
        "url-test" | "fallback" | "load-balance" | "smart"
    ) && group.proxies.len() >= 2
    {
        let timing = group.proxies.pop().unwrap_or_default();
        group.url = group.proxies.pop().unwrap_or_default();
        let timing_parts = timing.split(',').collect::<Vec<_>>();
        group.interval = timing_parts
            .first()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        group.timeout = timing_parts
            .get(1)
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        group.tolerance = timing_parts
            .get(2)
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
    }
    Some(group)
}

fn parse_ini_cron_task(value: &str) -> Option<CronTaskConfig> {
    let parts = value.split('`').map(str::trim).collect::<Vec<_>>();
    if parts.len() < 3 || parts[0].is_empty() || parts[1].is_empty() || parts[2].is_empty() {
        return None;
    }
    Some(CronTaskConfig {
        name: parts[0].to_string(),
        cron_exp: parts[1].to_string(),
        path: parts[2].to_string(),
        timeout: parts
            .get(3)
            .and_then(|value| value.parse().ok())
            .unwrap_or(3),
    })
}

fn toml_cron_tasks(root: &toml::Value) -> Vec<CronTaskConfig> {
    root.get("tasks")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|task| {
            Some(CronTaskConfig {
                name: task.get("name")?.as_str()?.to_string(),
                cron_exp: task.get("cronexp")?.as_str()?.to_string(),
                path: task.get("path")?.as_str()?.to_string(),
                timeout: task
                    .get("timeout")
                    .and_then(toml::Value::as_integer)
                    .unwrap_or(3) as i32,
            })
        })
        .collect()
}

fn yaml_cron_tasks(root: &serde_yaml::Value) -> Vec<CronTaskConfig> {
    root.get("tasks")
        .and_then(serde_yaml::Value::as_sequence)
        .into_iter()
        .flatten()
        .filter_map(|task| {
            Some(CronTaskConfig {
                name: task.get("name")?.as_str()?.to_string(),
                cron_exp: task.get("cronexp")?.as_str()?.to_string(),
                path: task.get("path")?.as_str()?.to_string(),
                timeout: task
                    .get("timeout")
                    .and_then(serde_yaml::Value::as_i64)
                    .unwrap_or(3) as i32,
            })
        })
        .collect()
}

fn toml_template_vars(root: &toml::Value) -> BTreeMap<String, String> {
    root.get("globals")
        .and_then(toml::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    Some((
                        item.get("key").and_then(toml_string)?.to_string(),
                        item.get("value").and_then(toml_string)?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn yaml_template_vars(root: &serde_yaml::Value) -> BTreeMap<String, String> {
    root.get("globals")
        .and_then(serde_yaml::Value::as_sequence)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    Some((
                        item.get("key").and_then(yaml_string)?.to_string(),
                        item.get("value").and_then(yaml_string)?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}
