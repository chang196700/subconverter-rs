use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulesetOutput {
    Surge,
    QuanX,
    ClashDomainProvider,
    ClashIpCidrProvider,
    SurgeDomainSet,
    ClashClassicalProvider,
}

impl RulesetOutput {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "1" => Ok(Self::Surge),
            "2" => Ok(Self::QuanX),
            "3" => Ok(Self::ClashDomainProvider),
            "4" => Ok(Self::ClashIpCidrProvider),
            "5" => Ok(Self::SurgeDomainSet),
            "6" => Ok(Self::ClashClassicalProvider),
            other => Err(Error::InvalidRequest(format!(
                "invalid ruleset type: {other}"
            ))),
        }
    }
}

pub fn convert_ruleset(content: &str, output: RulesetOutput, group: Option<&str>) -> String {
    let normalized = normalize_rules(content);
    match output {
        RulesetOutput::Surge => filter_rule_lines(&normalized, surge_rule_type).join("\n"),
        RulesetOutput::QuanX => to_quanx_rules(&normalized, group.unwrap_or("Proxy")).join("\n"),
        RulesetOutput::ClashDomainProvider => provider_yaml(domain_payload(&normalized, true)),
        RulesetOutput::ClashIpCidrProvider => provider_yaml(ip_payload(&normalized)),
        RulesetOutput::SurgeDomainSet => domain_payload(&normalized, false).join("\n"),
        RulesetOutput::ClashClassicalProvider => {
            provider_yaml(filter_rule_lines(&normalized, clash_rule_type))
        }
    }
}

fn normalize_rules(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.split("//").next().unwrap_or("").trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                None
            } else {
                Some(normalize_rule_line(line))
            }
        })
        .collect()
}

fn normalize_rule_line(line: &str) -> String {
    let mut parts = line
        .split(',')
        .map(|part| part.trim().to_string())
        .collect::<Vec<_>>();
    if parts.is_empty() {
        return String::new();
    }
    parts[0] = match parts[0].to_ascii_uppercase().as_str() {
        "HOST" => "DOMAIN".to_string(),
        "HOST-SUFFIX" => "DOMAIN-SUFFIX".to_string(),
        "HOST-KEYWORD" => "DOMAIN-KEYWORD".to_string(),
        "IP6-CIDR" => "IP-CIDR6".to_string(),
        other => other.to_string(),
    };
    parts.join(",")
}

fn provider_yaml(payload: Vec<String>) -> String {
    let mut output = String::from("payload:\n");
    for item in payload {
        output.push_str("  - ");
        output.push_str(&quote_yaml_scalar(&item));
        output.push('\n');
    }
    output
}

fn quote_yaml_scalar(value: &str) -> String {
    if value.contains(',') || value.contains(':') || value.starts_with('+') {
        format!("'{}'", value.replace('\'', "''"))
    } else {
        value.to_string()
    }
}

fn domain_payload(lines: &[String], clash_provider: bool) -> Vec<String> {
    lines
        .iter()
        .filter_map(|line| {
            let parts = line.split(',').map(str::trim).collect::<Vec<_>>();
            match parts.as_slice() {
                ["DOMAIN", domain, ..] => Some((*domain).to_string()),
                ["DOMAIN-SUFFIX", domain, ..] if clash_provider => Some(format!(".{domain}")),
                ["DOMAIN-SUFFIX", domain, ..] => Some((*domain).to_string()),
                _ => None,
            }
        })
        .collect()
}

fn ip_payload(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter_map(|line| {
            let parts = line.split(',').map(str::trim).collect::<Vec<_>>();
            match parts.as_slice() {
                ["IP-CIDR", cidr, ..] | ["IP-CIDR6", cidr, ..] => Some((*cidr).to_string()),
                _ => None,
            }
        })
        .collect()
}

fn to_quanx_rules(lines: &[String], group: &str) -> Vec<String> {
    lines
        .iter()
        .filter_map(|line| {
            let mut parts = line.split(',').map(str::trim).collect::<Vec<_>>();
            if parts.is_empty() || !quanx_rule_type(parts[0]) {
                return None;
            }
            if parts[0] == "IP-CIDR6" {
                parts[0] = "IP6-CIDR";
            }
            if parts.len() >= 2 {
                Some(format!("{},{},{}", parts[0], parts[1], group))
            } else {
                None
            }
        })
        .collect()
}

fn filter_rule_lines(lines: &[String], predicate: fn(&str) -> bool) -> Vec<String> {
    lines
        .iter()
        .filter(|line| line.split(',').next().map(predicate).unwrap_or(false))
        .cloned()
        .collect()
}

fn clash_rule_type(rule_type: &str) -> bool {
    matches!(
        rule_type,
        "DOMAIN"
            | "DOMAIN-SUFFIX"
            | "DOMAIN-KEYWORD"
            | "IP-CIDR"
            | "IP-CIDR6"
            | "SRC-IP-CIDR"
            | "GEOIP"
            | "MATCH"
            | "FINAL"
            | "SRC-PORT"
            | "DST-PORT"
            | "PROCESS-NAME"
    )
}

fn surge_rule_type(rule_type: &str) -> bool {
    matches!(
        rule_type,
        "DOMAIN"
            | "DOMAIN-SUFFIX"
            | "DOMAIN-KEYWORD"
            | "IP-CIDR"
            | "IP-CIDR6"
            | "SRC-IP-CIDR"
            | "GEOIP"
            | "MATCH"
            | "FINAL"
            | "USER-AGENT"
            | "URL-REGEX"
            | "PROCESS-NAME"
            | "IN-PORT"
            | "DEST-PORT"
            | "SRC-IP"
    )
}

fn quanx_rule_type(rule_type: &str) -> bool {
    matches!(
        rule_type,
        "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "IP-CIDR" | "IP-CIDR6" | "GEOIP"
    )
}
