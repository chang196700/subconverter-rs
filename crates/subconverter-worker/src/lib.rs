#[cfg(feature = "cloudflare")]
mod cloudflare {
    use std::collections::BTreeMap;

    use async_trait::async_trait;
    use subconverter_core::{
        expand_imports_with, handle_request_with_context, import_refs, AdapterCapabilities,
        CoreRequest, Error, FetchRequest, FetchedContent, Method, PlatformIo, RuntimeContext,
        Settings,
    };
    use worker::*;

    #[event(fetch)]
    pub async fn fetch(mut req: Request, env: Env, _ctx: Context) -> Result<Response> {
        let url = req.url()?;
        let method = match req.method() {
            worker::Method::Get => Method::Get,
            worker::Method::Head => Method::Head,
            worker::Method::Post => Method::Post,
            _ => Method::Get,
        };
        let body = if method == Method::Post {
            req.text().await.unwrap_or_default()
        } else {
            String::new()
        };
        let mut headers = BTreeMap::new();
        if let Some(user_agent) = worker_header(&req, "user-agent") {
            headers.insert("user-agent".to_string(), user_agent);
        }
        let request = CoreRequest {
            method,
            path: url.path().to_string(),
            query: url.query().unwrap_or("").to_string(),
            body,
            headers,
        };
        let io = WorkerIo { env: env.clone() };
        let mut settings = io
            .load_settings()
            .await
            .unwrap_or_else(|_| Settings::default());
        settings.apply_env(|key| worker_var(&env, key));
        let now_millis = Date::now().as_millis();
        let context = RuntimeContext::deterministic(now_millis / 1_000, now_millis);
        let response = handle_request_with_context(&io, &mut settings, request, context).await;
        let mut out = Response::from_bytes(response.body.into_bytes())?;
        out.headers_mut()
            .set("content-type", &response.content_type)?;
        for (key, value) in response.headers {
            out.headers_mut().set(&key, &value)?;
        }
        let out = out.with_status(response.status);
        Ok(out)
    }

    #[derive(Clone)]
    struct WorkerIo {
        env: Env,
    }

    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    impl PlatformIo for WorkerIo {
        async fn fetch_url(&self, url: &str) -> subconverter_core::Result<String> {
            Ok(self.fetch(&FetchRequest::new(url)).await?.body)
        }

        async fn fetch_url_with_headers(
            &self,
            url: &str,
        ) -> subconverter_core::Result<FetchedContent> {
            self.fetch(&FetchRequest::new(url)).await
        }

        async fn fetch(&self, request: &FetchRequest) -> subconverter_core::Result<FetchedContent> {
            let mut current =
                Url::parse(&request.url).map_err(|err| Error::Forbidden(err.to_string()))?;
            for redirect_count in 0..=request.max_redirects {
                validate_worker_url(&current, request)?;
                let mut init = RequestInit::new();
                init.with_method(worker::Method::Get)
                    .with_redirect(RequestRedirect::Manual);
                let outgoing = Request::new_with_init(current.as_str(), &init)
                    .map_err(|err| Error::Upstream(err.to_string()))?;
                for (key, value) in &request.headers {
                    outgoing
                        .headers()
                        .set(key, value)
                        .map_err(|err| Error::InvalidRequest(err.to_string()))?;
                }
                let mut response = Fetch::Request(outgoing)
                    .send()
                    .await
                    .map_err(|err| Error::Upstream(format!("worker fetch failed: {err}")))?;
                let status = response.status_code();
                if (300..400).contains(&status) {
                    if redirect_count == request.max_redirects {
                        return Err(Error::Upstream(format!(
                            "redirect limit exceeded for {}",
                            request.url
                        )));
                    }
                    let location = response
                        .headers()
                        .get("Location")
                        .map_err(|err| Error::Upstream(err.to_string()))?
                        .ok_or_else(|| {
                            Error::Upstream(format!(
                                "redirect response from {current} has no Location"
                            ))
                        })?;
                    current = current
                        .join(&location)
                        .map_err(|err| Error::Upstream(format!("invalid redirect URL: {err}")))?;
                    continue;
                }
                if let Ok(Some(length)) = response.headers().get("Content-Length") {
                    if length
                        .parse::<usize>()
                        .is_ok_and(|length| length > request.max_bytes)
                    {
                        return Err(Error::PayloadTooLarge {
                            limit: request.max_bytes,
                        });
                    }
                }
                let headers = response
                    .headers()
                    .entries()
                    .map(|(key, value)| (key, value))
                    .collect::<BTreeMap<_, _>>();
                let bytes = response
                    .bytes()
                    .await
                    .map_err(|err| Error::Upstream(format!("worker fetch body failed: {err}")))?;
                if bytes.len() > request.max_bytes {
                    return Err(Error::PayloadTooLarge {
                        limit: request.max_bytes,
                    });
                }
                let body = String::from_utf8(bytes)
                    .map_err(|err| Error::Upstream(format!("upstream body is not UTF-8: {err}")))?;
                return Ok(FetchedContent {
                    body,
                    headers,
                    status,
                    final_url: current.to_string(),
                });
            }
            Err(Error::Upstream("redirect processing failed".to_string()))
        }

        async fn read_file(&self, path: &str) -> subconverter_core::Result<String> {
            let kv = self.asset_kv()?;
            let key = normalize_asset_key(path);
            kv.get(&key)
                .text()
                .await
                .map_err(|err| Error::Io(format!("worker kv read failed for {key}: {err}")))?
                .ok_or_else(|| Error::Io(format!("worker asset not found: {key}")))
        }

        async fn write_file(
            &self,
            path: &str,
            content: &str,
            overwrite: bool,
        ) -> subconverter_core::Result<()> {
            let kv = self.config_kv()?;
            let key = normalize_asset_key(path);
            if !overwrite
                && kv
                    .get(&key)
                    .text()
                    .await
                    .map_err(|err| Error::Io(format!("worker kv read failed for {key}: {err}")))?
                    .is_some()
            {
                return Err(Error::Io(format!("worker asset already exists: {key}")));
            }
            kv.put(&key, content)
                .map_err(|err| Error::Io(format!("worker kv put failed for {key}: {err}")))?
                .execute()
                .await
                .map_err(|err| Error::Io(format!("worker kv write failed for {key}: {err}")))
        }

        async fn flush_cache(&self) -> subconverter_core::Result<()> {
            Err(Error::UnsupportedAdapterFeature("flushcache".to_string()))
        }

        async fn cache_get(
            &self,
            namespace: &str,
            key: &str,
        ) -> subconverter_core::Result<Option<FetchedContent>> {
            let kv = self.cache_kv()?;
            kv.get(&cache_key(namespace, key))
                .json::<FetchedContent>()
                .await
                .map_err(|err| Error::Io(format!("worker cache read failed: {err}")))
        }

        async fn cache_put(
            &self,
            namespace: &str,
            key: &str,
            content: &FetchedContent,
            ttl_seconds: u64,
        ) -> subconverter_core::Result<()> {
            let kv = self.cache_kv()?;
            kv.put(&cache_key(namespace, key), content)
                .map_err(|err| Error::Io(format!("worker cache put failed: {err}")))?
                .expiration_ttl(ttl_seconds.max(60))
                .execute()
                .await
                .map_err(|err| Error::Io(format!("worker cache write failed: {err}")))
        }

        fn capabilities(&self) -> AdapterCapabilities {
            AdapterCapabilities {
                persistent_config: false,
                cache_management: false,
                local_files: true,
                trusted_local_files: false,
                raw_fetch_routes: false,
                local_management_routes: false,
                scripts: false,
                cron: false,
                gist_upload: false,
            }
        }
    }

    impl WorkerIo {
        fn asset_kv(&self) -> subconverter_core::Result<worker::kv::KvStore> {
            let binding =
                worker_var(&self.env, "ASSET_KV_BINDING").unwrap_or_else(|| "ASSETS".to_string());
            self.env
                .kv(&binding)
                .map_err(|err| Error::Io(format!("missing worker KV binding {binding}: {err}")))
        }

        fn config_kv(&self) -> subconverter_core::Result<worker::kv::KvStore> {
            let binding = worker_var(&self.env, "CONFIG_KV_BINDING")
                .or_else(|| worker_var(&self.env, "ASSET_KV_BINDING"))
                .unwrap_or_else(|| "ASSETS".to_string());
            self.env
                .kv(&binding)
                .map_err(|err| Error::Io(format!("missing worker KV binding {binding}: {err}")))
        }

        fn cache_kv(&self) -> subconverter_core::Result<worker::kv::KvStore> {
            let binding = worker_var(&self.env, "CACHE_KV_BINDING")
                .or_else(|| worker_var(&self.env, "CONFIG_KV_BINDING"))
                .unwrap_or_else(|| "CONFIG".to_string());
            self.env
                .kv(&binding)
                .map_err(|err| Error::Io(format!("missing worker KV binding {binding}: {err}")))
        }

        async fn load_settings(&self) -> subconverter_core::Result<Settings> {
            let kv = self.config_kv()?;
            for key in ["pref.toml", "pref.yml", "pref.yaml", "pref.ini"] {
                let Some(mut content) = kv.get(key).text().await.map_err(|err| {
                    Error::Io(format!("worker config read failed for {key}: {err}"))
                })?
                else {
                    continue;
                };
                for _ in 0..8 {
                    let refs = import_refs(&content);
                    if refs.is_empty() {
                        return Settings::detect_and_parse(&content);
                    }
                    let mut imports = BTreeMap::new();
                    for reference in refs {
                        let normalized = normalize_asset_key(&reference);
                        let imported = kv
                            .get(&normalized)
                            .text()
                            .await
                            .map_err(|err| {
                                Error::Io(format!(
                                    "worker config import read failed for {normalized}: {err}"
                                ))
                            })?
                            .ok_or_else(|| {
                                Error::Io(format!("worker config import not found: {normalized}"))
                            })?;
                        imports.insert(reference, imported);
                    }
                    content = expand_imports_with(&content, |reference| {
                        imports
                            .get(reference)
                            .cloned()
                            .ok_or_else(|| Error::Io(format!("missing import: {reference}")))
                    })?;
                }
                return Err(Error::Parse(
                    "worker config import recursion limit exceeded".to_string(),
                ));
            }
            Ok(Settings::default())
        }
    }

    fn worker_var(env: &Env, key: &str) -> Option<String> {
        env.var(key)
            .map(|value| value.to_string())
            .or_else(|_| env.secret(key).map(|value| value.to_string()))
            .ok()
    }

    fn worker_header(req: &Request, key: &str) -> Option<String> {
        req.headers().get(key).ok().flatten()
    }

    fn normalize_asset_key(path: &str) -> String {
        path.trim_start_matches("file://")
            .trim_start_matches('/')
            .trim_start_matches('\\')
            .replace('\\', "/")
    }

    fn cache_key(namespace: &str, key: &str) -> String {
        let hash = key
            .as_bytes()
            .iter()
            .fold(0xcbf29ce484222325_u64, |hash, byte| {
                (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
            });
        format!("cache:{namespace}:{hash:016x}")
    }

    fn validate_worker_url(url: &Url, request: &FetchRequest) -> subconverter_core::Result<()> {
        match url.scheme() {
            "https" => {}
            "http" if request.allow_plain_http => {}
            "http" => {
                return Err(Error::Forbidden(
                    "plain HTTP upstreams are disabled".to_string(),
                ));
            }
            scheme => {
                return Err(Error::Forbidden(format!(
                    "unsupported upstream URL scheme: {scheme}"
                )));
            }
        }
        if !request.allow_private_network {
            let host = url
                .host_str()
                .ok_or_else(|| Error::Forbidden("upstream URL has no host".to_string()))?;
            if matches!(
                host.trim_end_matches('.').to_ascii_lowercase().as_str(),
                "localhost" | "metadata" | "metadata.google.internal" | "instance-data"
            ) || host.ends_with(".localhost")
                || host.parse::<std::net::IpAddr>().is_ok_and(is_non_public_ip)
            {
                return Err(Error::Forbidden(format!(
                    "non-public upstream host is blocked: {host}"
                )));
            }
        }
        Ok(())
    }

    fn is_non_public_ip(ip: std::net::IpAddr) -> bool {
        match ip {
            std::net::IpAddr::V4(ip) => {
                let octets = ip.octets();
                ip.is_private()
                    || ip.is_loopback()
                    || ip.is_link_local()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || ip.is_broadcast()
                    || ip.is_documentation()
                    || octets[0] == 0
                    || octets[0] >= 240
                    || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                    || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
            }
            std::net::IpAddr::V6(ip) => {
                if let Some(mapped) = ip.to_ipv4_mapped() {
                    return is_non_public_ip(mapped.into());
                }
                let segments = ip.segments();
                ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || ip.is_unique_local()
                    || ip.is_unicast_link_local()
                    || segments[0] == 0x2001 && segments[1] == 0x0db8
            }
        }
    }
}

#[cfg(not(feature = "cloudflare"))]
pub fn worker_feature_disabled() -> &'static str {
    "build with --features cloudflare for Cloudflare Worker"
}
