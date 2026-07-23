use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;
use subconverter_core::util::url_encode;
use subconverter_core::{
    convert_subscription, handle_request, ConvertRequest, CoreRequest, MemoryIo, Method, Proxy,
    Settings, SurgeVersion, Target,
};

#[derive(Debug, Deserialize)]
struct CaseManifest {
    #[serde(rename = "case")]
    cases: Vec<GoldenCase>,
}

#[derive(Debug, Deserialize)]
struct GoldenCase {
    name: String,
    target: String,
    input: String,
    golden: String,
    config: Option<String>,
    surge_version: Option<u8>,
}

#[test]
fn golden_fixtures_match() {
    assert_manifest_matches("cases.toml");
}

#[test]
fn full_semantic_golden_fixtures_match() {
    assert_manifest_matches("cases.full.toml");
}

fn assert_manifest_matches(manifest_name: &str) {
    let fixtures = fixture_root();
    let manifest_path = fixtures.join(manifest_name);
    let manifest_content =
        fs::read_to_string(&manifest_path).expect("tests/fixtures manifest should be readable");
    let manifest: CaseManifest = toml::from_str(&manifest_content).expect("manifest should parse");

    assert!(
        !manifest.cases.is_empty(),
        "{manifest_name} should contain at least one golden case"
    );

    for case in manifest.cases {
        let input = read_fixture(&fixtures, &case.input);
        let config = case
            .config
            .as_ref()
            .map(|path| read_fixture(&fixtures, path));
        let output = render_case(&fixtures, &case, input, config);
        let expected = read_fixture(&fixtures, &case.golden);

        assert_semantic_eq(&case, &expected, &output, manifest_name);
    }
}

fn render_case(
    fixtures: &Path,
    case: &GoldenCase,
    input: String,
    config: Option<String>,
) -> String {
    if let Some(config) = config {
        return render_route_case(fixtures, case, &input, &config);
    }
    convert_subscription(ConvertRequest {
        target: Target::parse(&case.target).expect("target should be supported"),
        sources: vec![input],
        config: None,
        user_agent: None,
        surge_version: case
            .surge_version
            .map(SurgeVersion::try_from)
            .transpose()
            .expect("Surge version should be supported"),
        options: Default::default(),
    })
    .unwrap_or_else(|err| panic!("case {} conversion failed: {err}", case.name))
}

fn render_route_case(fixtures: &Path, case: &GoldenCase, input: &str, config: &str) -> String {
    let io = add_base_files(MemoryIo::default(), fixtures);
    let mut query = format!(
        "target={}&url={}&config={}",
        url_encode(&case.target),
        url_encode(input.trim()),
        url_encode(config)
    );
    if let Some(version) = case.surge_version {
        query.push_str("&ver=");
        query.push_str(&version.to_string());
    }
    let request = CoreRequest {
        method: Method::Get,
        path: "/sub".to_string(),
        query,
        body: String::new(),
        headers: Default::default(),
    };
    let mut settings = Settings::default();
    tokio::runtime::Runtime::new()
        .expect("tokio runtime should start")
        .block_on(async { handle_request(&io, &mut settings, request).await.body })
}

fn add_base_files(mut io: MemoryIo, fixtures: &Path) -> MemoryIo {
    let _ = fixtures;
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let base = workspace.join("base");
    for path in [
        "simple_base.yml",
        "surge.conf",
        "surfboard.conf",
        "quan.conf",
        "quanx.conf",
        "loon.conf",
        "mellow.conf",
        "shadowsocks_base.json",
        "singbox.json",
    ] {
        let content = read_fixture(&base, path);
        io = io.with_file(format!("base/{path}"), content);
    }
    io
}

#[test]
fn full_golden_manifest_declares_required_targets() {
    let fixtures = fixture_root();
    let manifest_path = fixtures.join("cases.full.toml");
    let manifest_content = fs::read_to_string(&manifest_path)
        .expect("tests/fixtures/cases.full.toml should be readable");
    let manifest: CaseManifest =
        toml::from_str(&manifest_content).expect("cases.full.toml should parse");

    let declared = manifest
        .cases
        .iter()
        .map(|case| match (case.target.as_str(), case.surge_version) {
            ("surge", Some(version)) => format!("surge-v{version}"),
            (target, _) => target.to_string(),
        })
        .collect::<std::collections::BTreeSet<_>>();

    let required = [
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
        "surge-v2",
        "surge-v3",
        "surge-v4",
        "v2ray",
        "singbox",
        "mellow",
        "mixed",
        "trojan",
    ];
    for target in required {
        assert!(
            declared.contains(target),
            "cases.full.toml should declare target {target}"
        );
    }
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
}

fn read_fixture(root: &Path, relative: &str) -> String {
    let path = root.join(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("fixture {} should be readable: {err}", path.display()))
}

fn assert_semantic_eq(case: &GoldenCase, expected: &str, actual: &str, manifest_name: &str) {
    let result = match case.target.as_str() {
        "clash" | "clashr" => compare_yaml(expected, actual),
        "singbox" | "sssub" => compare_json(expected, actual),
        "ssd" => compare_ssd(expected, actual),
        "ss" | "ssr" | "v2ray" | "trojan" | "mixed" => compare_encoded_links(expected, actual),
        "surge" | "surfboard" | "quan" | "quanx" | "loon" | "mellow" => {
            compare_text_config(expected, actual)
        }
        target => Err(format!("no semantic comparator for target {target}")),
    };
    if let Err(reason) = result {
        panic!(
            "semantic golden mismatch for case {} in {manifest_name}: {reason}\n--- expected ---\n{}\n--- actual ---\n{}",
            case.name, expected, actual
        );
    }
}

fn compare_yaml(expected: &str, actual: &str) -> Result<(), String> {
    let expected = canonical_yaml(expected)?;
    let actual = canonical_yaml(actual)?;
    (expected == actual)
        .then_some(())
        .ok_or_else(|| format!("YAML values differ: expected {expected:?}, actual {actual:?}"))
}

fn canonical_yaml(content: &str) -> Result<Value, String> {
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(content).map_err(|err| format!("invalid YAML: {err}"))?;
    let mut value = serde_json::to_value(yaml).map_err(|err| err.to_string())?;
    let Some(root) = value.as_object_mut() else {
        return Err("YAML root is not a mapping".to_string());
    };
    for (legacy, modern) in [
        ("Proxy", "proxies"),
        ("Proxy Group", "proxy-groups"),
        ("Rule", "rules"),
    ] {
        if let Some(value) = root.remove(legacy) {
            root.insert(modern.to_string(), value);
        }
    }
    if let Some(proxies) = root.get_mut("proxies").and_then(Value::as_array_mut) {
        for proxy in proxies {
            let Some(proxy) = proxy.as_object_mut() else {
                continue;
            };
            let mut ws_options = proxy
                .remove("ws-opts")
                .and_then(|value| value.as_object().cloned())
                .unwrap_or_default();
            if let Some(path) = proxy.remove("ws-path") {
                ws_options.insert("path".to_string(), path);
            }
            if let Some(headers) = proxy.remove("ws-headers") {
                ws_options.insert("headers".to_string(), headers);
            }
            if !ws_options.is_empty() {
                proxy.insert("ws-opts".to_string(), Value::Object(ws_options));
            }
        }
    }
    Ok(value)
}

fn compare_json(expected: &str, actual: &str) -> Result<(), String> {
    let expected: Value =
        serde_json::from_str(expected).map_err(|err| format!("invalid expected JSON: {err}"))?;
    let actual: Value =
        serde_json::from_str(actual).map_err(|err| format!("invalid actual JSON: {err}"))?;
    (expected == actual)
        .then_some(())
        .ok_or_else(|| format!("JSON values differ: expected {expected:?}, actual {actual:?}"))
}

fn compare_ssd(expected: &str, actual: &str) -> Result<(), String> {
    let expected = expected
        .trim()
        .strip_prefix("ssd://")
        .ok_or_else(|| "expected SSD output has no ssd:// prefix".to_string())?;
    let actual = actual
        .trim()
        .strip_prefix("ssd://")
        .ok_or_else(|| "actual SSD output has no ssd:// prefix".to_string())?;
    compare_json(
        &subconverter_core::util::base64_decode(expected)
            .map_err(|err| format!("invalid expected SSD payload: {err}"))?,
        &subconverter_core::util::base64_decode(actual)
            .map_err(|err| format!("invalid actual SSD payload: {err}"))?,
    )
}

fn compare_encoded_links(expected: &str, actual: &str) -> Result<(), String> {
    let expected = decode_links(expected)?;
    let actual = decode_links(actual)?;
    (expected == actual).then_some(()).ok_or_else(|| {
        format!("decoded proxy links differ: expected {expected:?}, actual {actual:?}")
    })
}

fn decode_links(content: &str) -> Result<Vec<Proxy>, String> {
    let decoded = subconverter_core::util::base64_decode(content.trim())
        .map_err(|err| format!("invalid subscription base64: {err}"))?;
    subconverter_core::convert::parse_subscription_source(&decoded)
        .map_err(|err| format!("invalid decoded subscription: {err}"))
}

fn compare_text_config(expected: &str, actual: &str) -> Result<(), String> {
    let expected = canonical_text_config(expected);
    let actual = canonical_text_config(actual);
    (expected == actual).then_some(()).ok_or_else(|| {
        format!("text config fields differ: expected {expected:?}, actual {actual:?}")
    })
}

fn canonical_text_config(content: &str) -> Vec<(String, Vec<String>)> {
    let mut sections = Vec::<(String, Vec<String>)>::new();
    let mut current = String::new();
    for raw_line in content.replace("\r\n", "\n").lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            current = line[1..line.len() - 1].trim().to_ascii_lowercase();
            if !sections.iter().any(|(name, _)| name == &current) {
                sections.push((current.clone(), Vec::new()));
            }
            continue;
        }
        let normalized = normalize_config_line(line);
        if let Some((_, lines)) = sections.iter_mut().find(|(name, _)| name == &current) {
            lines.push(normalized);
        } else {
            sections.push((current.clone(), vec![normalized]));
        }
    }
    for (section, lines) in &mut sections {
        if !matches!(
            section.as_str(),
            "proxy"
                | "server"
                | "server_local"
                | "policy"
                | "proxy group"
                | "rule"
                | "filter_local"
                | "routingrule"
                | "endpoint"
                | "endpointgroup"
                | "tcp"
                | "dnsserver"
                | "dnsrule"
        ) {
            lines.sort();
        }
    }
    sections
}

fn normalize_config_line(line: &str) -> String {
    if let Some((key, value)) = line.split_once('=') {
        format!("{}={}", key.trim(), normalize_comma_separated(value.trim()))
    } else {
        normalize_comma_separated(line)
    }
}

fn normalize_comma_separated(value: &str) -> String {
    value
        .split(',')
        .map(|part| part.trim().trim_matches('"'))
        .collect::<Vec<_>>()
        .join(",")
}
