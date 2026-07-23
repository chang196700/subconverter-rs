pub mod config;
pub mod convert;
pub mod error;
pub mod io;
pub mod model;
pub mod routes;
pub mod rules;
pub mod template;
pub mod util;

pub use config::{expand_imports_with, import_refs, ConfigFormat, SecuritySettings, Settings};
pub use convert::{
    convert_subscription, convert_subscription_with_context, convert_subscription_with_settings,
    execute_background_script, execute_subscription_script, ConvertOptions, ConvertRequest,
    RuntimeContext, SurgeVersion, Target,
};
pub use error::{Error, Result};
pub use io::{
    AdapterCapabilities, FetchRequest, FetchedContent, MemoryIo, PlatformIo, UploadedContent,
};
pub use model::{Proxy, ProxyType, TriBool};
pub use routes::{handle_request, CoreRequest, CoreResponse, Method};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
