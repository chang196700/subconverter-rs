use subconverter_core::util::{base64_decode, base64_encode};
use subconverter_core::{convert_subscription, ConvertOptions, ConvertRequest, Target};

#[test]
fn ss_to_clash_smoke_fixture() {
    let output = convert_subscription(ConvertRequest {
        target: Target::Clash,
        sources: vec!["ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Example".to_string()],
        config: None,
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("conversion should succeed");

    assert!(output.contains("name: Example"));
    assert!(output.contains("server: example.com"));
    assert!(output.contains("cipher: aes-128-gcm"));
}

#[test]
fn base64_multiline_subscription_to_clash() {
    let subscription = [
        "ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Example",
        "trojan://secret@example.org:443#Trojan",
    ]
    .join("\n");
    let output = convert_subscription(ConvertRequest {
        target: Target::Clash,
        sources: vec![base64_encode(&subscription)],
        config: None,
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("conversion should succeed");

    assert!(output.contains("name: Example"));
    assert!(output.contains("name: Trojan"));
    assert!(output.contains("type: trojan"));
}

#[test]
fn ssr_round_trip_link_export() {
    let raw = "example.com:8388:origin:aes-128-cfb:plain:cGFzcw==/?remarks=U1NSIEV4YW1wbGU=&group=R3JvdXA=";
    let source = format!("ssr://{}", base64_encode(raw));
    let output = convert_subscription(ConvertRequest {
        target: Target::ShadowsocksR,
        sources: vec![source],
        config: None,
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("conversion should succeed");

    let decoded = base64_decode(output.trim()).expect("SSR subscription should decode");
    assert!(decoded.starts_with("ssr://"));
}

#[test]
fn node_group_option_overrides_exported_ssr_group() {
    let raw = "example.com:8388:origin:aes-128-cfb:plain:cGFzcw==/?remarks=U1NSIEV4YW1wbGU=&group=R3JvdXA=";
    let output = convert_subscription(ConvertRequest {
        target: Target::ShadowsocksR,
        sources: vec![format!("ssr://{}", base64_encode(raw))],
        config: None,
        user_agent: None,
        surge_version: None,
        options: ConvertOptions {
            node_group: Some("Custom".to_string()),
            ..ConvertOptions::default()
        },
    })
    .expect("conversion should succeed");

    let decoded = base64_decode(output.trim()).expect("SSR subscription should decode");
    let payload = decoded
        .strip_prefix("ssr://")
        .and_then(|value| subconverter_core::util::base64_decode(value).ok())
        .expect("ssr output should decode");
    assert!(payload.contains(&format!("group={}", base64_encode("Custom"))));
}

#[test]
fn telegram_like_http_link_to_clash() {
    let output = convert_subscription(ConvertRequest {
        target: Target::Clash,
        sources: vec![
            "tg://http?server=1.2.3.4&port=8080&user=user&pass=pass&remark=HTTPNode".to_string(),
        ],
        config: None,
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("conversion should succeed");

    assert!(output.contains("name: 1.2.3.4:8080"));
    assert!(output.contains("username: user"));
    assert!(output.contains("password: pass"));
}

#[test]
fn singbox_exports_legacy_protocol_details() {
    let ssr_raw =
        "ssr.example.com:8388:auth_sha1_v4:aes-128-cfb:tls1.2_ticket_auth:cGFzcw==/?remarks=U1NS";
    let yaml_source = r#"
proxies:
  - name: PluginSS
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-128-gcm
    password: pass
    plugin: simple-obfs
    plugin-opts: obfs=http;obfs-host=plugin.example.com
  - name: VMessTLS
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000003
    alterId: 0
    tls: true
    servername: tls.example.com
  - name: SocksAuth
    type: socks5
    server: socks.example.com
    port: 1080
    username: user
    password: pass
  - name: HttpAuth
    type: http
    server: http.example.com
    port: 8080
    username: http-user
    password: http-pass
"#;
    let output = convert_subscription(ConvertRequest {
        target: Target::SingBox,
        sources: vec![
            yaml_source.to_string(),
            format!("ssr://{}", base64_encode(ssr_raw)),
            "https://https-user:https-pass@https.example.com:8443#HttpsAuth".to_string(),
        ],
        config: None,
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("singbox conversion should succeed");

    assert!(output.contains("\"tag\": \"PluginSS\""));
    assert!(output.contains("\"plugin\": \"obfs-local\""));
    assert!(output.contains("\"plugin_opts\": \"obfs=http;obfs-host=plugin.example.com\""));
    assert!(output.contains("\"tag\": \"SSR\""));
    assert!(output.contains("\"type\": \"shadowsocksr\""));
    assert!(output.contains("\"protocol\": \"auth_sha1_v4\""));
    assert!(output.contains("\"obfs\": \"tls1.2_ticket_auth\""));
    assert!(output.contains("\"tag\": \"VMessTLS\""));
    assert!(output.contains("\"tls\": {"));
    assert!(output.contains("\"server_name\": \"tls.example.com\""));
    assert!(output.contains("\"insecure\": false"));
    assert!(output.contains("\"tag\": \"SocksAuth\""));
    assert!(output.contains("\"version\": \"5\""));
    assert!(output.contains("\"username\": \"user\""));
    assert!(output.contains("\"password\": \"pass\""));
    assert!(output.contains("\"tag\": \"HttpAuth\""));
    assert!(output.contains("\"username\": \"http-user\""));
    assert!(output.contains("\"password\": \"http-pass\""));
    assert!(output.contains("\"tag\": \"HttpsAuth\""));
    assert!(output.contains("\"username\": \"https-user\""));
    assert!(output.contains("\"password\": \"https-pass\""));
}

#[test]
fn ss_to_ssd_export_is_supported() {
    let output = convert_subscription(ConvertRequest {
        target: Target::Ssd,
        sources: vec!["ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Example".to_string()],
        config: None,
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("conversion should succeed");

    assert!(output.starts_with("ssd://"));
}

#[test]
fn sssub_exports_sip008_json_and_merges_base() {
    let source = [
        "ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#SSNode",
        "trojan://secret@example.org:443#TrojanNode",
    ]
    .join("\n");
    let config = r#"
sssub_rule_base = '''
{
  "route": "bypass-lan-china",
  "remote_dns": "dns.google",
  "proxy_apps": {
    "enabled": false,
    "bypass": true
  },
  "remarks": "Old",
  "server": "old.example.com"
}
'''
"#;
    let output = convert_subscription(ConvertRequest {
        target: Target::ShadowsocksSub,
        sources: vec![source],
        config: Some(config.to_string()),
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("sssub conversion should succeed");

    assert!(!output.contains("ss://"));
    assert!(!output.contains("TrojanNode"));
    let parsed: serde_json::Value = serde_json::from_str(&output).expect("output should be json");
    let servers = parsed.as_array().expect("sssub output should be an array");
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0]["route"], "bypass-lan-china");
    assert_eq!(servers[0]["remote_dns"], "dns.google");
    assert_eq!(servers[0]["proxy_apps"]["bypass"], true);
    assert_eq!(servers[0]["remarks"], "SSNode");
    assert_eq!(servers[0]["server"], "example.com");
    assert_eq!(servers[0]["server_port"], 8388);
    assert_eq!(servers[0]["method"], "aes-128-gcm");
    assert_eq!(servers[0]["password"], "pass");
    assert_eq!(servers[0]["plugin"], "");
    assert_eq!(servers[0]["plugin_opts"], "");
}

#[test]
fn clash_yaml_source_to_singbox() {
    let source = r#"
proxies:
  - name: ClashSS
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-128-gcm
    password: pass
  - name: ClashVMess
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    alterId: 0
    network: ws
    tls: true
    ws-opts:
      path: /ws
      headers:
        Host: edge.example.com
"#;
    let output = convert_subscription(ConvertRequest {
        target: Target::SingBox,
        sources: vec![source.to_string()],
        config: None,
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("conversion should succeed");

    assert!(output.contains("\"tag\": \"ClashSS\""));
    assert!(output.contains("\"type\": \"shadowsocks\""));
    assert!(output.contains("\"tag\": \"ClashVMess\""));
    assert!(output.contains("\"type\": \"vmess\""));
    assert!(output.contains("\"uuid\": \"00000000-0000-0000-0000-000000000000\""));
    assert!(output.contains("\"alter_id\": 0"));
    assert!(output.contains("\"security\": \"auto\""));
    assert!(output.contains("\"transport\": {"));
    assert!(output.contains("\"type\": \"ws\""));
    assert!(output.contains("\"path\": \"/ws\""));
    assert!(output.contains("\"Host\": \"edge.example.com\""));
}

#[test]
fn clash_vmess_transport_options_round_trip_to_clash() {
    let source = r#"
proxies:
  - name: VMessWS
    type: vmess
    server: ws.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
    alterId: 0
    network: ws
    tls: true
    servername: tls.example.com
    ws-opts:
      path: /ws
      headers:
        Host: edge.example.com
  - name: VMessH2
    type: vmess
    server: h2.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000001
    alterId: 0
    network: h2
    tls: true
    h2-opts:
      path: /h2
      host:
        - h2-host.example.com
  - name: VMessGrpc
    type: vmess
    server: grpc.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000002
    alterId: 0
    network: grpc
    tls: true
    grpc-opts:
      grpc-service-name: svc
"#;
    let output = convert_subscription(ConvertRequest {
        target: Target::Clash,
        sources: vec![source.to_string()],
        config: None,
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("conversion should succeed");

    assert!(output.contains("name: VMessWS"));
    assert!(output.contains("servername: tls.example.com"));
    assert!(output.contains("ws-opts:"));
    assert!(output.contains("path: /ws"));
    assert!(output.contains("Host: edge.example.com"));
    assert!(output.contains("name: VMessH2"));
    assert!(output.contains("h2-opts:"));
    assert!(output.contains("path: /h2"));
    assert!(output.contains("- h2-host.example.com"));
    assert!(output.contains("name: VMessGrpc"));
    assert!(output.contains("grpc-opts:"));
    assert!(output.contains("grpc-service-name: svc"));

    let singbox = convert_subscription(ConvertRequest {
        target: Target::SingBox,
        sources: vec![source.to_string()],
        config: None,
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("singbox conversion should succeed");
    assert!(singbox.contains("\"tag\": \"VMessWS\""));
    assert!(singbox.contains("\"uuid\": \"00000000-0000-0000-0000-000000000000\""));
    assert!(singbox.contains("\"alter_id\": 0"));
    assert!(singbox.contains("\"security\": \"auto\""));
    assert!(singbox.contains("\"transport\": {"));
    assert!(singbox.contains("\"type\": \"ws\""));
    assert!(singbox.contains("\"path\": \"/ws\""));
    assert!(singbox.contains("\"Host\": \"edge.example.com\""));
    assert!(singbox.contains("\"tag\": \"VMessGrpc\""));
    assert!(singbox.contains("\"type\": \"grpc\""));
    assert!(singbox.contains("\"service_name\": \"svc\""));
}

#[test]
fn trojan_transport_options_export_to_clash() {
    let yaml_source = r#"
proxies:
  - name: TrojanWS
    type: trojan
    server: ws.example.com
    port: 443
    password: secret
    sni: tls.example.com
    network: ws
    ws-opts:
      path: /trojan-ws
      headers:
        Host: edge.example.com
"#;
    let direct_source = "trojan://secret@grpc.example.com:443?type=grpc&serviceName=trojan-svc&sni=grpc-tls.example.com&skip-cert-verify=true#TrojanGrpc";
    let output = convert_subscription(ConvertRequest {
        target: Target::Clash,
        sources: vec![yaml_source.to_string(), direct_source.to_string()],
        config: None,
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("conversion should succeed");

    assert!(output.contains("name: TrojanWS"));
    assert!(output.contains("type: trojan"));
    assert!(output.contains("sni: tls.example.com"));
    assert!(output.contains("network: ws"));
    assert!(output.contains("path: /trojan-ws"));
    assert!(output.contains("Host: edge.example.com"));
    assert!(output.contains("name: TrojanGrpc"));
    assert!(output.contains("network: grpc"));
    assert!(output.contains("grpc-service-name: trojan-svc"));
    assert!(output.contains("sni: grpc-tls.example.com"));
    assert!(output.contains("skip-cert-verify: true"));

    let singbox = convert_subscription(ConvertRequest {
        target: Target::SingBox,
        sources: vec![yaml_source.to_string(), direct_source.to_string()],
        config: None,
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("singbox conversion should succeed");
    assert!(singbox.contains("\"tag\": \"TrojanWS\""));
    assert!(singbox.contains("\"type\": \"trojan\""));
    assert!(singbox.contains("\"password\": \"secret\""));
    assert!(singbox.contains("\"transport\": {"));
    assert!(singbox.contains("\"type\": \"ws\""));
    assert!(singbox.contains("\"path\": \"/trojan-ws\""));
    assert!(singbox.contains("\"Host\": \"edge.example.com\""));
    assert!(singbox.contains("\"tag\": \"TrojanGrpc\""));
    assert!(singbox.contains("\"type\": \"grpc\""));
    assert!(singbox.contains("\"service_name\": \"trojan-svc\""));
}

#[test]
fn sip008_json_source_to_clash() {
    let source = r#"
{
  "servers": [
    {
      "remarks": "SIP008",
      "server": "sip.example.com",
      "port": 8388,
      "encryption": "aes-256-gcm",
      "password": "secret"
    }
  ]
}
"#;
    let output = convert_subscription(ConvertRequest {
        target: Target::Clash,
        sources: vec![source.to_string()],
        config: None,
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("conversion should succeed");

    assert!(output.contains("name: SIP008"));
    assert!(output.contains("cipher: aes-256-gcm"));
    assert!(output.contains("server: sip.example.com"));
}

#[test]
fn target_specific_text_exports_have_expected_sections() {
    let source = "ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Example";

    let surge = convert_subscription(ConvertRequest {
        target: Target::Surge,
        sources: vec![source.to_string()],
        config: None,
        user_agent: None,
        surge_version: Some(subconverter_core::SurgeVersion::V4),
        options: Default::default(),
    })
    .expect("surge conversion should succeed");
    assert!(surge.contains("[Proxy]"));
    assert!(surge.contains("Example = ss, example.com, 8388"));
    assert!(surge.contains("[Rule]"));

    let quanx = convert_subscription(ConvertRequest {
        target: Target::QuanX,
        sources: vec![source.to_string()],
        config: None,
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("quanx conversion should succeed");
    assert!(quanx.contains("shadowsocks = example.com:8388"));
    assert!(quanx.contains("tag=Example"));

    let loon = convert_subscription(ConvertRequest {
        target: Target::Loon,
        sources: vec![source.to_string()],
        config: None,
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("loon conversion should succeed");
    assert!(loon.contains("[Proxy]"));
    assert!(loon.contains("Example = Shadowsocks, example.com, 8388"));
}

#[test]
fn surge_versions_apply_distinct_protocol_capabilities() {
    let source = [
        "ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#SS",
        "vmess://eyJ2IjoiMiIsInBzIjoiVk1lc3MiLCJhZGQiOiJ2bWVzcy5leGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMSIsImFpZCI6IjAiLCJuZXQiOiJ3cyIsImhvc3QiOiJ3cy5leGFtcGxlLmNvbSIsInBhdGgiOiIvd3MiLCJ0bHMiOiJ0bHMifQ==",
    ]
    .join("\n");
    let convert = |version| {
        convert_subscription(ConvertRequest {
            target: Target::Surge,
            sources: vec![source.clone()],
            config: None,
            user_agent: None,
            surge_version: version,
            options: Default::default(),
        })
        .expect("Surge conversion should succeed")
    };

    let v2 = convert(Some(subconverter_core::SurgeVersion::V2));
    let v3 = convert(Some(subconverter_core::SurgeVersion::V3));
    let default_version = convert(None);
    let v4 = convert(Some(subconverter_core::SurgeVersion::V4));

    assert!(v2.contains("SS = custom,"));
    assert!(!v2.contains("VMess = vmess,"));
    assert!(v3.contains("SS = ss,"));
    assert!(!v3.contains("VMess = vmess,"));
    assert_eq!(default_version, v3);
    assert!(v4.contains("VMess = vmess,"));
}

#[test]
fn unsupported_protocols_are_filtered_without_http_fallback() {
    let output = convert_subscription(ConvertRequest {
        target: Target::Mellow,
        sources: vec![
            "tg://socks?server=socks.example.com&port=1080&user=user&pass=pass".to_string(),
        ],
        config: None,
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("unsupported nodes should be filtered");

    assert!(!output.contains("socks.example.com"));
    assert!(!output.contains("http, socks.example.com"));
}

#[test]
fn malformed_base64_returns_a_clear_client_error() {
    let error = convert_subscription(ConvertRequest {
        target: Target::Clash,
        sources: vec!["%%%not-base64%%%".to_string()],
        config: None,
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect_err("malformed input must not produce an empty successful config");

    assert_eq!(error.status_code(), 400);
    assert!(error.to_string().contains("No nodes were found"));
}

#[test]
fn duplicate_unicode_names_are_stably_disambiguated() {
    let source = [
        "ss://YWVzLTEyOC1nY206cGFzcw==@one.example.com:8388#%E8%8A%82%E7%82%B9%3D%E9%A6%99%E6%B8%AF",
        "ss://YWVzLTEyOC1nY206cGFzcw==@two.example.com:8388#%E8%8A%82%E7%82%B9%3D%E9%A6%99%E6%B8%AF",
    ]
    .join("\n");
    let output = convert_subscription(ConvertRequest {
        target: Target::Clash,
        sources: vec![source],
        config: None,
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("Unicode conversion should succeed");

    let first = output.find("name: 节点-香港").expect("first name");
    let second = output.find("name: 节点-香港 2").expect("second name");
    assert!(first < second);
}

#[test]
fn text_targets_merge_configured_rule_base_sections() {
    let source = "ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Example";

    let surge_config = r#"
surge_rule_base = '''
[General]
loglevel = notify

[Proxy]
DIRECT = direct

[Proxy Group]
Existing = select,DIRECT

[Rule]
DOMAIN,example.test,DIRECT
'''
overwrite_original_rules = false
"#;
    let surge = convert_subscription(ConvertRequest {
        target: Target::Surge,
        sources: vec![source.to_string()],
        config: Some(surge_config.to_string()),
        user_agent: None,
        surge_version: Some(subconverter_core::SurgeVersion::V4),
        options: Default::default(),
    })
    .expect("surge conversion should succeed");
    assert!(surge.contains("[General]"));
    assert!(surge.contains("DIRECT = direct"));
    assert!(surge.contains("Existing = select,DIRECT"));
    assert!(surge.contains("DOMAIN,example.test,DIRECT"));
    assert!(surge.contains("Example = ss, example.com, 8388"));
    assert!(surge.contains("Proxy = select,Example"));
    assert!(surge.contains("FINAL,Proxy"));

    let quanx_config = r#"
quanx_rule_base = '''
[general]
server_check_url=http://www.gstatic.com/generate_204

[server_local]
local = direct

[filter_local]
'''
"#;
    let quanx = convert_subscription(ConvertRequest {
        target: Target::QuanX,
        sources: vec![source.to_string()],
        config: Some(quanx_config.to_string()),
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("quanx conversion should succeed");
    assert!(quanx.contains("[general]"));
    assert!(quanx.contains("local = direct"));
    assert!(quanx.contains("shadowsocks = example.com:8388"));
    assert!(quanx.contains("[filter_local]"));

    let loon_config = r#"
loon_rule_base = '''
[General]
allow-udp-proxy = false

[Proxy]

[Proxy Group]
Existing = select, DIRECT

[Rule]
DOMAIN,example.test,DIRECT
'''
overwrite_original_rules = false
"#;
    let loon = convert_subscription(ConvertRequest {
        target: Target::Loon,
        sources: vec![source.to_string()],
        config: Some(loon_config.to_string()),
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("loon conversion should succeed");
    assert!(loon.contains("allow-udp-proxy = false"));
    assert!(loon.contains("Example = Shadowsocks, example.com, 8388"));
    assert!(loon.contains("Existing = select, DIRECT"));
    assert!(loon.contains("Proxy = select, Example"));
    assert!(loon.contains("DOMAIN,example.test,DIRECT"));
}

#[test]
fn text_target_nodelist_skips_rule_base_merge() {
    let source = "ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Example";
    let config = r#"
surge_rule_base = '''
[General]
loglevel = notify
'''
"#;
    let output = convert_subscription(ConvertRequest {
        target: Target::Surge,
        sources: vec![source.to_string()],
        config: Some(config.to_string()),
        user_agent: None,
        surge_version: Some(subconverter_core::SurgeVersion::V4),
        options: ConvertOptions {
            nodelist: subconverter_core::TriBool::True,
            ..Default::default()
        },
    })
    .expect("surge nodelist conversion should succeed");
    assert!(!output.contains("loglevel = notify"));
    assert!(output.contains("Example = ss, example.com, 8388"));
}

#[test]
fn config_filters_renames_and_adds_emoji() {
    let source = [
        "ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#HK%20Node",
        "ss://YWVzLTEyOC1nY206cGFzcw==@example.net:8388#US%20Node",
    ]
    .join("\n");
    let config = r#"
[node_pref]
include_remarks = HK
rename_node = HK@Hong Kong

[emojis]
add_emoji = true
emoji = Hong Kong,🇭🇰
"#;
    let output = convert_subscription(ConvertRequest {
        target: Target::Clash,
        sources: vec![source],
        config: Some(config.to_string()),
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("conversion should succeed");

    assert!(output.contains("name: 🇭🇰 Hong Kong Node"));
    assert!(!output.contains("US Node"));
}

#[test]
fn emoji_rules_require_add_emoji_enabled() {
    let config = r#"
[emojis]
emoji = HK,🇭🇰
"#;
    let output = convert_subscription(ConvertRequest {
        target: Target::Clash,
        sources: vec!["ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#HK%20Node".to_string()],
        config: Some(config.to_string()),
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("conversion should succeed");

    assert!(output.contains("name: HK Node"));
    assert!(!output.contains("🇭🇰 HK Node"));
}

#[test]
fn emoji_config_can_remove_old_emoji() {
    let config = r#"
[emojis]
remove_old_emoji = true
"#;
    let output = convert_subscription(ConvertRequest {
        target: Target::Clash,
        sources: vec![
            "ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#%F0%9F%87%AD%F0%9F%87%B0%20HK%20Node"
                .to_string(),
        ],
        config: Some(config.to_string()),
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("conversion should succeed");

    assert!(output.contains("name: HK Node"));
    assert!(!output.contains("🇭🇰 HK Node"));
}

#[test]
fn yaml_emoji_rules_are_supported() {
    let config = r#"
emojis:
  add_emoji: true
  rules:
  - {match: HK, emoji: 🇭🇰}
"#;
    let output = convert_subscription(ConvertRequest {
        target: Target::Clash,
        sources: vec!["ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#HK%20Node".to_string()],
        config: Some(config.to_string()),
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("conversion should succeed");

    assert!(output.contains("name: 🇭🇰 HK Node"));
}

#[test]
fn toml_node_pref_config_is_applied() {
    let config = r#"
[node_pref]
exclude_remarks = ["Drop"]

[[node_pref.rename_node]]
match = "Keep"
replace = "Kept"
"#;
    let output = convert_subscription(ConvertRequest {
        target: Target::Clash,
        sources: vec![
            "ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#Keep".to_string(),
            "ss://YWVzLTEyOC1nY206cGFzcw==@example.net:8388#Drop".to_string(),
        ],
        config: Some(config.to_string()),
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("conversion should succeed");

    assert!(output.contains("name: Kept"));
    assert!(!output.contains("Drop"));
}

#[test]
fn toml_custom_groups_and_rulesets_feed_clash_output() {
    let config = r#"
[[custom_groups]]
name = "Auto"
type = "url-test"
rule = [".*", "[]DIRECT"]
use = ["airport-a", "airport-b"]
url = "http://www.gstatic.com/generate_204"
interval = 300
timeout = 5000
tolerance = 100
disable_udp = true

[[rulesets]]
group = "DIRECT"
ruleset = "[]GEOIP,CN"

[[rulesets]]
group = "Auto"
ruleset = "[]FINAL"
"#;
    let output = convert_subscription(ConvertRequest {
        target: Target::Clash,
        sources: vec![
            "ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#NodeA".to_string(),
            "ss://YWVzLTEyOC1nY206cGFzcw==@example.net:8388#NodeB".to_string(),
        ],
        config: Some(config.to_string()),
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("conversion should succeed");

    assert!(output.contains("name: Auto"));
    assert!(output.contains("type: url-test"));
    assert!(output.contains("url: http://www.gstatic.com/generate_204"));
    assert!(output.contains("use:"));
    assert!(output.contains("- airport-a"));
    assert!(output.contains("- airport-b"));
    assert!(output.contains("timeout: 5000"));
    assert!(output.contains("GEOIP,CN,DIRECT"));
    assert!(output.contains("disable-udp: true"));
    assert!(output.contains("MATCH,Auto"));
}

#[test]
fn ini_custom_group_feeds_clash_output() {
    let config = r#"
[rulesets]
custom_proxy_group=Proxy`select`.*`[]DIRECT
ruleset=DIRECT,[]GEOIP,CN
ruleset=Proxy,[]FINAL
"#;
    let output = convert_subscription(ConvertRequest {
        target: Target::Clash,
        sources: vec!["ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#NodeA".to_string()],
        config: Some(config.to_string()),
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("conversion should succeed");

    assert!(output.contains("name: Proxy"));
    assert!(output.contains("- NodeA"));
    assert!(output.contains("- DIRECT"));
    assert!(output.contains("GEOIP,CN,DIRECT"));
    assert!(output.contains("MATCH,Proxy"));
}

#[test]
fn clash_output_merges_inline_base_config() {
    let config = r#"
clash_rule_base = '''
mixed-port: 7890
mode: Rule
dns:
  enable: true
proxies:
  - name: Old
    type: http
    server: old.example.com
    port: 80
rules:
  - MATCH,Old
'''
"#;
    let output = convert_subscription(ConvertRequest {
        target: Target::Clash,
        sources: vec!["ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#NodeA".to_string()],
        config: Some(config.to_string()),
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("conversion should succeed");

    assert!(output.contains("mixed-port"));
    assert!(output.contains("7890"));
    assert!(output.contains("mode: Rule"));
    assert!(output.contains("enable: true"));
    assert!(output.contains("name: NodeA"));
    assert!(output.contains("MATCH,Proxy"));
    assert!(!output.contains("old.example.com"));
}

#[test]
fn singbox_output_merges_inline_base_config() {
    let config = r#"
singbox_rule_base = '''
{
  "log": {
    "level": "debug"
  },
  "dns": {
    "servers": [
      {
        "tag": "dns_direct",
        "address": "1.1.1.1"
      }
    ]
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen_port": 2080
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "Old"
    }
  ],
  "route": {
    "auto_detect_interface": true,
    "rules": [
      {
        "outbound": "DIRECT"
      }
    ]
  }
}
'''
"#;
    let output = convert_subscription(ConvertRequest {
        target: Target::SingBox,
        sources: vec!["ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#NodeA".to_string()],
        config: Some(config.to_string()),
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("singbox conversion should succeed");

    assert!(output.contains("\"level\": \"debug\""));
    assert!(output.contains("\"dns\": {"));
    assert!(output.contains("\"listen_port\": 2080"));
    assert!(output.contains("\"auto_detect_interface\": true"));
    assert!(output.contains("\"rules\": ["));
    assert!(output.contains("\"tag\": \"NodeA\""));
    assert!(output.contains("\"type\": \"shadowsocks\""));
    assert!(!output.contains("\"tag\": \"Old\""));
}

#[test]
fn singbox_nodelist_skips_rule_base_merge() {
    let config = r#"
singbox_rule_base = '''
{
  "log": {
    "level": "debug"
  },
  "outbounds": []
}
'''
"#;
    let output = convert_subscription(ConvertRequest {
        target: Target::SingBox,
        sources: vec!["ss://YWVzLTEyOC1nY206cGFzcw==@example.com:8388#NodeA".to_string()],
        config: Some(config.to_string()),
        user_agent: None,
        surge_version: None,
        options: ConvertOptions {
            nodelist: subconverter_core::TriBool::True,
            ..Default::default()
        },
    })
    .expect("singbox conversion should succeed");

    assert!(output.contains("\"outbounds\": ["));
    assert!(output.contains("\"tag\": \"NodeA\""));
    assert!(!output.contains("\"level\": \"debug\""));
}

#[test]
fn clash_yaml_modern_protocols_export_to_clash_and_singbox() {
    let source = r#"
proxies:
  - name: WG
    type: wireguard
    server: wg.example.com
    port: 51820
    ip: 172.16.0.2/32
    private-key: private
    public-key: public
    pre-shared-key: psk
    dns: [1.1.1.1]
    mtu: 1280
  - name: HY
    type: hysteria
    server: hy.example.com
    port: 443
    auth-str: auth
    protocol: udp
    obfs: salamander
    obfs-protocol: salamander
    up: 20 Mbps
    up-speed: 20
    down: 100 Mbps
    down-speed: 100
    sni: hy.example.com
    fingerprint: chrome
    alpn: [h3]
    skip-cert-verify: true
  - name: HY2
    type: hysteria2
    server: hy2.example.com
    port: 443
    password: pass
    obfs: salamander
    obfs-password: obfs-pass
    up: 10 Mbps
    down: 50 Mbps
    sni: hy2.example.com
    fingerprint: firefox
    alpn: [h3]
"#;
    let clash = convert_subscription(ConvertRequest {
        target: Target::Clash,
        sources: vec![source.to_string()],
        config: None,
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("clash conversion should succeed");
    assert!(clash.contains("type: wireguard"));
    assert!(clash.contains("private-key: private"));
    assert!(clash.contains("preshared-key: psk"));
    assert!(clash.contains("type: hysteria"));
    assert!(clash.contains("auth-str: auth"));
    assert!(clash.contains("obfs-protocol: salamander"));
    assert!(clash.contains("up: 20 Mbps"));
    assert!(clash.contains("up-speed: 20"));
    assert!(clash.contains("down: 100 Mbps"));
    assert!(clash.contains("down-speed: 100"));
    assert!(clash.contains("fingerprint: chrome"));
    assert!(clash.contains("type: hysteria2"));
    assert!(clash.contains("obfs-password: obfs-pass"));
    assert!(clash.contains("up: 10 Mbps"));
    assert!(clash.contains("down: 50 Mbps"));
    assert!(clash.contains("fingerprint: firefox"));
    assert!(clash.contains("- h3"));

    let singbox = convert_subscription(ConvertRequest {
        target: Target::SingBox,
        sources: vec![source.to_string()],
        config: None,
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("singbox conversion should succeed");
    assert!(singbox.contains("\"type\": \"wireguard\""));
    assert!(singbox.contains("\"peers\": ["));
    assert!(singbox.contains("\"public_key\": \"public\""));
    assert!(singbox.contains("\"pre_shared_key\": \"psk\""));
    assert!(singbox.contains("\"allowed_ips\": ["));
    assert!(singbox.contains("\"mtu\": 1280"));
    assert!(singbox.contains("\"type\": \"hysteria\""));
    assert!(singbox.contains("\"auth_str\": \"auth\""));
    assert!(singbox.contains("\"auth\": \"YXV0aA==\""));
    assert!(singbox.contains("\"up_mbps\": 20"));
    assert!(singbox.contains("\"down_mbps\": 100"));
    assert!(singbox.contains("\"tls\": {"));
    assert!(singbox.contains("\"insecure\": true"));
    assert!(singbox.contains("\"type\": \"hysteria2\""));
    assert!(singbox.contains("\"obfs\": {"));
    assert!(singbox.contains("\"password\": \"obfs-pass\""));
}

#[test]
fn modern_protocol_direct_links_export_to_clash_and_singbox() {
    let source = [
        "wireguard://public@wg.example.com:51820?private-key=private&ip=172.16.0.2%2F32&dns=1.1.1.1,8.8.8.8&mtu=1280#WG",
        "hysteria://hy.example.com:443?auth-str=auth&protocol=udp&obfs=salamander&obfs-protocol=salamander&sni=hy.example.com&fingerprint=chrome&alpn=h3,h2&up=20%20Mbps&down=100%20Mbps&up-speed=20&down-speed=100&skip-cert-verify=true#HY",
        "hy2://pass@hy2.example.com:443?obfs=salamander&obfs-password=obfs-pass&sni=hy2.example.com&fingerprint=firefox&alpn=h3&up=10%20Mbps&down=50%20Mbps#HY2",
    ]
    .join("\n");

    let clash = convert_subscription(ConvertRequest {
        target: Target::Clash,
        sources: vec![source.clone()],
        config: None,
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("clash conversion should succeed");
    assert!(clash.contains("name: WG"));
    assert!(clash.contains("type: wireguard"));
    assert!(clash.contains("private-key: private"));
    assert!(clash.contains("ip: 172.16.0.2/32"));
    assert!(clash.contains("type: hysteria"));
    assert!(clash.contains("auth-str: auth"));
    assert!(clash.contains("obfs-protocol: salamander"));
    assert!(clash.contains("fingerprint: chrome"));
    assert!(clash.contains("skip-cert-verify: true"));
    assert!(clash.contains("type: hysteria2"));
    assert!(clash.contains("password: pass"));
    assert!(clash.contains("obfs-password: obfs-pass"));
    assert!(clash.contains("fingerprint: firefox"));

    let singbox = convert_subscription(ConvertRequest {
        target: Target::SingBox,
        sources: vec![source],
        config: None,
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("singbox conversion should succeed");
    assert!(singbox.contains("\"type\": \"wireguard\""));
    assert!(singbox.contains("\"peers\": ["));
    assert!(singbox.contains("\"public_key\": \"public\""));
    assert!(singbox.contains("\"local_address\": ["));
    assert!(singbox.contains("\"172.16.0.2/32\""));
    assert!(singbox.contains("\"allowed_ips\": ["));
    assert!(singbox.contains("\"mtu\": 1280"));
    assert!(singbox.contains("\"type\": \"hysteria\""));
    assert!(singbox.contains("\"auth_str\": \"auth\""));
    assert!(singbox.contains("\"auth\": \"YXV0aA==\""));
    assert!(singbox.contains("\"up_mbps\": 20"));
    assert!(singbox.contains("\"down_mbps\": 100"));
    assert!(singbox.contains("\"type\": \"hysteria2\""));
    assert!(singbox.contains("\"password\": \"pass\""));
    assert!(singbox.contains("\"obfs\": {"));
    assert!(singbox.contains("\"password\": \"obfs-pass\""));
}

#[test]
fn snell_yaml_and_direct_links_export_to_clash_and_singbox() {
    let yaml_source = r#"
proxies:
  - name: SnellYAML
    type: snell
    server: snell.example.com
    port: 44046
    psk: secret
    version: 3
    obfs-opts:
      mode: http
      host: example.com
"#;
    let direct_source =
        "snell://direct-secret@direct.example.com:44046?version=2&obfs=tls&obfs-host=host.example#SnellDirect";

    let clash = convert_subscription(ConvertRequest {
        target: Target::Clash,
        sources: vec![yaml_source.to_string(), direct_source.to_string()],
        config: None,
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("clash conversion should succeed");
    assert!(clash.contains("name: SnellYAML"));
    assert!(clash.contains("type: snell"));
    assert!(clash.contains("psk: secret"));
    assert!(clash.contains("version: 3"));
    assert!(clash.contains("mode: http"));
    assert!(clash.contains("name: SnellDirect"));
    assert!(clash.contains("psk: direct-secret"));
    assert!(clash.contains("host: host.example"));

    let singbox = convert_subscription(ConvertRequest {
        target: Target::SingBox,
        sources: vec![yaml_source.to_string(), direct_source.to_string()],
        config: None,
        user_agent: None,
        surge_version: None,
        options: Default::default(),
    })
    .expect("singbox conversion should succeed");
    assert!(singbox.contains("\"type\": \"snell\""));
    assert!(singbox.contains("\"password\": \"secret\""));
    assert!(singbox.contains("\"version\": 3"));
    assert!(singbox.contains("\"obfs\": \"http\""));
    assert!(singbox.contains("\"password\": \"direct-secret\""));
    assert!(singbox.contains("\"obfs_host\": \"host.example\""));
}
