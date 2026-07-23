#![cfg(feature = "quickjs")]

use subconverter_core::{
    convert_subscription_with_settings, ConvertOptions, ConvertRequest, RuntimeContext, Settings,
    Target,
};

const SOURCE: &str = concat!(
    "ss://YWVzLTEyOC1nY206cGFzcw@example.com:8388#Drop\n",
    "ss://YWVzLTEyOC1nY206cGFzcw@example.net:8388#Keep\n"
);

#[test]
fn authorized_quickjs_filter_and_rename_are_applied() {
    let mut settings = Settings {
        enable_filter: true,
        filter_script: "function filter(node) { return node.Remark.includes('Keep'); }".to_string(),
        ..Settings::default()
    };
    settings
        .rename_node
        .push(subconverter_core::model::RegexMatchConfig {
            script: Some("function rename(node) { return 'JS ' + node.Remark; }".to_string()),
            r#match: String::new(),
            replace: String::new(),
        });

    let output = convert_subscription_with_settings(
        ConvertRequest {
            target: Target::Clash,
            sources: vec![SOURCE.to_string()],
            config: None,
            user_agent: None,
            surge_version: None,
            options: ConvertOptions::default(),
        },
        Some(settings),
        RuntimeContext::deterministic(1_700_000_000, 7).with_scripts_authorized(true),
    )
    .expect("authorized QuickJS conversion should succeed");

    assert!(output.contains("JS Keep"));
    assert!(!output.contains("Drop"));
}

#[test]
fn unauthorized_quickjs_is_rejected() {
    let settings = Settings {
        enable_filter: true,
        filter_script: "function filter() { return true; }".to_string(),
        ..Settings::default()
    };

    let error = convert_subscription_with_settings(
        ConvertRequest {
            target: Target::Clash,
            sources: vec![SOURCE.to_string()],
            config: None,
            user_agent: None,
            surge_version: None,
            options: ConvertOptions::default(),
        },
        Some(settings),
        RuntimeContext::deterministic(1_700_000_000, 7),
    )
    .expect_err("unauthorized scripts must fail");

    assert_eq!(error.status_code(), 403);
}

#[test]
fn quickjs_execution_deadline_is_enforced() {
    let settings = Settings {
        enable_filter: true,
        script_timeout_millis: 20,
        filter_script: "function filter() { while (true) {} return true; }".to_string(),
        ..Settings::default()
    };

    let error = convert_subscription_with_settings(
        ConvertRequest {
            target: Target::Clash,
            sources: vec![SOURCE.to_string()],
            config: None,
            user_agent: None,
            surge_version: None,
            options: ConvertOptions::default(),
        },
        Some(settings),
        RuntimeContext::deterministic(1_700_000_000, 7).with_scripts_authorized(true),
    )
    .expect_err("infinite scripts must time out");

    assert_eq!(error.status_code(), 504);
}
