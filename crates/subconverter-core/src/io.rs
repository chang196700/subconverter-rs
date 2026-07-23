use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FetchedContent {
    pub body: String,
    pub headers: BTreeMap<String, String>,
    pub status: u16,
    pub final_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRequest {
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub max_bytes: usize,
    pub connect_timeout_seconds: u64,
    pub request_timeout_seconds: u64,
    pub max_redirects: usize,
    pub allow_private_network: bool,
    pub allow_plain_http: bool,
}

impl FetchRequest {
    pub fn new(url: impl Into<String>) -> Self {
        let mut headers = BTreeMap::new();
        headers.insert(
            "User-Agent".to_string(),
            format!("subconverter-rs/{}", crate::VERSION),
        );
        Self {
            url: url.into(),
            headers,
            max_bytes: 1_048_576,
            connect_timeout_seconds: 10,
            request_timeout_seconds: 30,
            max_redirects: 5,
            allow_private_network: false,
            allow_plain_http: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdapterCapabilities {
    pub persistent_config: bool,
    pub cache_management: bool,
    pub local_files: bool,
    pub trusted_local_files: bool,
    pub raw_fetch_routes: bool,
    pub local_management_routes: bool,
    pub scripts: bool,
    pub cron: bool,
    pub gist_upload: bool,
}

impl Default for AdapterCapabilities {
    fn default() -> Self {
        Self {
            persistent_config: true,
            cache_management: true,
            local_files: true,
            trusted_local_files: false,
            raw_fetch_routes: true,
            local_management_routes: true,
            scripts: false,
            cron: false,
            gist_upload: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UploadedContent {
    pub name: String,
    pub path: String,
    pub content: String,
    pub write_managed_url: bool,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait PlatformIo: Send + Sync {
    async fn fetch_url(&self, url: &str) -> Result<String>;
    async fn fetch(&self, request: &FetchRequest) -> Result<FetchedContent> {
        let mut fetched = self.fetch_url_with_headers(&request.url).await?;
        if fetched.body.len() > request.max_bytes {
            return Err(Error::PayloadTooLarge {
                limit: request.max_bytes,
            });
        }
        if fetched.status == 0 {
            fetched.status = 200;
        }
        if fetched.final_url.is_empty() {
            fetched.final_url = request.url.clone();
        }
        Ok(fetched)
    }
    async fn fetch_url_with_headers(&self, url: &str) -> Result<FetchedContent> {
        Ok(FetchedContent {
            body: self.fetch_url(url).await?,
            headers: BTreeMap::new(),
            status: 200,
            final_url: url.to_string(),
        })
    }
    async fn read_file(&self, path: &str) -> Result<String>;
    async fn write_file(&self, path: &str, content: &str, overwrite: bool) -> Result<()>;
    async fn flush_cache(&self) -> Result<()>;
    async fn cache_get(&self, _namespace: &str, _key: &str) -> Result<Option<FetchedContent>> {
        Ok(None)
    }
    async fn cache_get_stale(
        &self,
        _namespace: &str,
        _key: &str,
    ) -> Result<Option<FetchedContent>> {
        Ok(None)
    }
    async fn cache_put(
        &self,
        _namespace: &str,
        _key: &str,
        _content: &FetchedContent,
        _ttl_seconds: u64,
    ) -> Result<()> {
        Ok(())
    }
    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities::default()
    }
    async fn upload_gist(
        &self,
        name: &str,
        path: &str,
        content: &str,
        write_managed_url: bool,
    ) -> Result<()> {
        let _ = (name, path, content, write_managed_url);
        Err(Error::UnsupportedAdapterFeature("gist upload".to_string()))
    }
}

#[derive(Debug, Clone, Default)]
pub struct MemoryIo {
    files: Arc<RwLock<BTreeMap<String, String>>>,
    urls: Arc<RwLock<BTreeMap<String, String>>>,
    url_headers: Arc<RwLock<BTreeMap<String, BTreeMap<String, String>>>>,
    uploads: Arc<RwLock<Vec<UploadedContent>>>,
}

impl MemoryIo {
    pub fn with_file(self, path: impl Into<String>, content: impl Into<String>) -> Self {
        self.files
            .write()
            .expect("lock poisoned")
            .insert(path.into(), content.into());
        self
    }

    pub fn with_url(self, url: impl Into<String>, content: impl Into<String>) -> Self {
        self.urls
            .write()
            .expect("lock poisoned")
            .insert(url.into(), content.into());
        self
    }

    pub fn with_url_header(
        self,
        url: impl Into<String>,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.url_headers
            .write()
            .expect("lock poisoned")
            .entry(url.into())
            .or_default()
            .insert(key.into(), value.into());
        self
    }

    pub fn uploads(&self) -> Vec<UploadedContent> {
        self.uploads.read().expect("lock poisoned").clone()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl PlatformIo for MemoryIo {
    async fn fetch_url(&self, url: &str) -> Result<String> {
        self.urls
            .read()
            .expect("lock poisoned")
            .get(url)
            .cloned()
            .ok_or_else(|| Error::Io(format!("url not found in memory backend: {url}")))
    }

    async fn fetch_url_with_headers(&self, url: &str) -> Result<FetchedContent> {
        Ok(FetchedContent {
            body: self.fetch_url(url).await?,
            headers: self
                .url_headers
                .read()
                .expect("lock poisoned")
                .get(url)
                .cloned()
                .unwrap_or_default(),
            status: 200,
            final_url: url.to_string(),
        })
    }

    async fn read_file(&self, path: &str) -> Result<String> {
        self.files
            .read()
            .expect("lock poisoned")
            .get(path)
            .cloned()
            .ok_or_else(|| Error::Io(format!("file not found in memory backend: {path}")))
    }

    async fn write_file(&self, path: &str, content: &str, overwrite: bool) -> Result<()> {
        let mut files = self.files.write().expect("lock poisoned");
        if !overwrite && files.contains_key(path) {
            return Err(Error::Io(format!("file already exists: {path}")));
        }
        files.insert(path.to_string(), content.to_string());
        Ok(())
    }

    async fn flush_cache(&self) -> Result<()> {
        Ok(())
    }

    async fn upload_gist(
        &self,
        name: &str,
        path: &str,
        content: &str,
        write_managed_url: bool,
    ) -> Result<()> {
        self.uploads
            .write()
            .expect("lock poisoned")
            .push(UploadedContent {
                name: name.to_string(),
                path: path.to_string(),
                content: content.to_string(),
                write_managed_url,
            });
        Ok(())
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            trusted_local_files: true,
            scripts: true,
            cron: true,
            gist_upload: true,
            ..AdapterCapabilities::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FetchRequest;

    #[test]
    fn fetch_requests_use_a_stable_default_user_agent() {
        let request = FetchRequest::new("https://example.com/subscription");

        assert_eq!(
            request.headers.get("User-Agent"),
            Some(&format!("subconverter-rs/{}", crate::VERSION))
        );
    }
}
