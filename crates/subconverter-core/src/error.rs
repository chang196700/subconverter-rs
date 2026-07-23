use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("unsupported target: {0}")]
    UnsupportedTarget(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("missing required argument: {0}")]
    MissingArgument(&'static str),
    #[error("unauthorized")]
    Unauthorized,
    #[error("request is forbidden: {0}")]
    Forbidden(String),
    #[error("payload exceeds the configured limit of {limit} bytes")]
    PayloadTooLarge { limit: usize },
    #[error("upstream request failed: {0}")]
    Upstream(String),
    #[error("upstream request timed out: {0}")]
    Timeout(String),
    #[error("io backend error: {0}")]
    Io(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("feature is not available on this adapter: {0}")]
    UnsupportedAdapterFeature(String),
}

impl Error {
    pub fn status_code(&self) -> u16 {
        match self {
            Error::Unauthorized | Error::Forbidden(_) => 403,
            Error::PayloadTooLarge { .. } => 413,
            Error::Upstream(_) => 502,
            Error::Timeout(_) => 504,
            Error::MissingArgument(_) | Error::InvalidRequest(_) | Error::UnsupportedTarget(_) => {
                400
            }
            Error::UnsupportedAdapterFeature(_) => 501,
            Error::Io(_) | Error::Parse(_) => 500,
        }
    }
}
