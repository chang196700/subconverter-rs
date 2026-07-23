use base64::{engine::general_purpose, Engine};
use percent_encoding::{percent_decode_str, utf8_percent_encode, NON_ALPHANUMERIC};
use std::collections::BTreeMap;
use url::form_urlencoded;

use crate::{Error, Result};

pub fn url_encode(input: &str) -> String {
    utf8_percent_encode(input, NON_ALPHANUMERIC).to_string()
}

pub fn url_decode(input: &str) -> String {
    percent_decode_str(input).decode_utf8_lossy().into_owned()
}

pub fn base64_decode(input: &str) -> Result<String> {
    let normalized = input.trim();
    let bytes = general_purpose::STANDARD
        .decode(normalized)
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(normalized))
        .map_err(|err| Error::Parse(format!("invalid base64: {err}")))?;
    String::from_utf8(bytes).map_err(|err| Error::Parse(format!("invalid utf-8: {err}")))
}

pub fn base64_encode(input: &str) -> String {
    general_purpose::STANDARD.encode(input)
}

pub fn url_safe_base64_decode(input: &str) -> Result<String> {
    let padded = match input.len() % 4 {
        0 => input.to_string(),
        n => format!("{}{}", input, "=".repeat(4 - n)),
    };
    let bytes = general_purpose::URL_SAFE
        .decode(padded)
        .map_err(|err| Error::Parse(format!("invalid url-safe base64: {err}")))?;
    String::from_utf8(bytes).map_err(|err| Error::Parse(format!("invalid utf-8: {err}")))
}

pub fn url_safe_base64_encode(input: &str) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(input)
}

pub fn parse_query(query: &str) -> BTreeMap<String, String> {
    form_urlencoded::parse(query.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

pub fn split_sources(input: &str) -> Vec<String> {
    input
        .split(['|', '\n', '\r'])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}
