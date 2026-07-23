use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriBool {
    True,
    False,
    #[default]
    Undefined,
}

impl TriBool {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Self::True,
            "false" | "0" | "no" | "off" => Self::False,
            _ => Self::Undefined,
        }
    }

    pub fn get(self, default: bool) -> bool {
        match self {
            Self::True => true,
            Self::False => false,
            Self::Undefined => default,
        }
    }

    pub fn or(self, fallback: Self) -> Self {
        match self {
            Self::Undefined => fallback,
            value => value,
        }
    }

    pub fn is_undef(self) -> bool {
        matches!(self, Self::Undefined)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyType {
    #[default]
    Unknown,
    Shadowsocks,
    ShadowsocksR,
    VMess,
    Trojan,
    Snell,
    Http,
    Https,
    Socks5,
    WireGuard,
    Hysteria,
    Hysteria2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proxy {
    pub proxy_type: ProxyType,
    pub id: u32,
    pub group_id: u32,
    pub group: String,
    pub remark: String,
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub encrypt_method: String,
    pub plugin: String,
    pub plugin_option: String,
    pub protocol: String,
    pub protocol_param: String,
    pub obfs: String,
    pub obfs_param: String,
    pub user_id: String,
    pub alter_id: u16,
    pub transfer_protocol: String,
    pub fake_type: String,
    pub tls_secure: bool,
    pub host: String,
    pub path: String,
    pub edge: String,
    pub quic_secure: String,
    pub quic_secret: String,
    pub udp: TriBool,
    pub tcp_fast_open: TriBool,
    pub allow_insecure: TriBool,
    pub tls13: TriBool,
    pub underlying_proxy: String,
    pub snell_version: u16,
    pub server_name: String,
    pub self_ip: String,
    pub self_ipv6: String,
    pub public_key: String,
    pub private_key: String,
    pub pre_shared_key: String,
    pub dns_servers: Vec<String>,
    pub mtu: u16,
    pub allowed_ips: String,
    pub keep_alive: u16,
    pub test_url: String,
    pub client_id: String,
    pub ports: String,
    pub up: String,
    pub up_speed: u32,
    pub down: String,
    pub down_speed: u32,
    pub auth_str: String,
    pub sni: String,
    pub fingerprint: String,
    pub ca: String,
    pub ca_str: String,
    pub recv_window_conn: u32,
    pub recv_window: u32,
    pub disable_mtu_discovery: TriBool,
    pub hop_interval: u32,
    pub alpn: Vec<String>,
    pub cwnd: u32,
}

impl Default for Proxy {
    fn default() -> Self {
        Self {
            proxy_type: ProxyType::Unknown,
            id: 0,
            group_id: 0,
            group: String::new(),
            remark: String::new(),
            hostname: String::new(),
            port: 0,
            username: String::new(),
            password: String::new(),
            encrypt_method: String::new(),
            plugin: String::new(),
            plugin_option: String::new(),
            protocol: String::new(),
            protocol_param: String::new(),
            obfs: String::new(),
            obfs_param: String::new(),
            user_id: String::new(),
            alter_id: 0,
            transfer_protocol: String::new(),
            fake_type: String::new(),
            tls_secure: false,
            host: String::new(),
            path: String::new(),
            edge: String::new(),
            quic_secure: String::new(),
            quic_secret: String::new(),
            udp: TriBool::Undefined,
            tcp_fast_open: TriBool::Undefined,
            allow_insecure: TriBool::Undefined,
            tls13: TriBool::Undefined,
            underlying_proxy: String::new(),
            snell_version: 0,
            server_name: String::new(),
            self_ip: String::new(),
            self_ipv6: String::new(),
            public_key: String::new(),
            private_key: String::new(),
            pre_shared_key: String::new(),
            dns_servers: Vec::new(),
            mtu: 0,
            allowed_ips: "0.0.0.0/0, ::/0".to_string(),
            keep_alive: 0,
            test_url: String::new(),
            client_id: String::new(),
            ports: String::new(),
            up: String::new(),
            up_speed: 0,
            down: String::new(),
            down_speed: 0,
            auth_str: String::new(),
            sni: String::new(),
            fingerprint: String::new(),
            ca: String::new(),
            ca_str: String::new(),
            recv_window_conn: 0,
            recv_window: 0,
            disable_mtu_discovery: TriBool::Undefined,
            hop_interval: 0,
            alpn: Vec::new(),
            cwnd: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RegexMatchConfig {
    pub script: Option<String>,
    pub r#match: String,
    pub replace: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RulesetConfig {
    pub group: String,
    pub url: String,
    pub interval: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProxyGroupConfig {
    pub name: String,
    pub group_type: String,
    pub url: String,
    pub interval: i32,
    pub timeout: i32,
    pub tolerance: i32,
    pub proxies: Vec<String>,
    pub providers: Vec<String>,
    pub disable_udp: TriBool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CronTaskConfig {
    pub name: String,
    pub cron_exp: String,
    pub path: String,
    pub timeout: i32,
}
