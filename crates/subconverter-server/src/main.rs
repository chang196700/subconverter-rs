use std::collections::BTreeMap;
use std::fs;
use std::future::IntoFuture;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method as AxumMethod, Uri};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use clap::{Args, Parser, Subcommand};
use http::StatusCode;
use subconverter_core::{
    execute_background_script, expand_imports_with, handle_request, AdapterCapabilities,
    CoreRequest, Error, FetchRequest, FetchedContent, Method, PlatformIo, Settings,
};
use tokio::sync::{watch, RwLock};

mod service;
#[cfg(windows)]
mod windows_service_host;

const GRACEFUL_SHUTDOWN_LIMIT: Duration = Duration::from_secs(30);

#[derive(Debug, Parser)]
#[command(name = "subconverter-server", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the HTTP server in the foreground.
    Serve(ServeArgs),
    /// Install and control the native operating-system service.
    Service(service::ServiceArgs),
    /// Internal Windows SCM entrypoint.
    #[cfg(windows)]
    #[command(name = "service-run", hide = true)]
    ServiceRun(ServeArgs),
}

#[derive(Debug, Clone, Args)]
struct ServeArgs {
    /// Directory containing pref.*, base/, profiles/, scripts/, and logs/.
    #[arg(long)]
    data_dir: Option<PathBuf>,
}

#[derive(Clone)]
struct AppState {
    settings: Arc<RwLock<Settings>>,
    io: FsIo,
}

fn main() -> ExitCode {
    match dispatch(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("subconverter-server: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(cli: Cli) -> Result<u8> {
    match cli.command {
        Some(Command::Service(args)) => service::execute(args),
        #[cfg(windows)]
        Some(Command::ServiceRun(args)) => {
            windows_service_host::run(args.data_dir)?;
            Ok(0)
        }
        Some(Command::Serve(args)) => {
            init_stderr_logging();
            run_foreground(args.data_dir)?;
            Ok(0)
        }
        None => {
            init_stderr_logging();
            run_foreground(None)?;
            Ok(0)
        }
    }
}

fn init_stderr_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

fn run_foreground(data_dir: Option<PathBuf>) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create async runtime")?;
    let result = runtime.block_on(run_server(data_dir, shutdown_signal(), |_| Ok(())));
    runtime.shutdown_timeout(Duration::ZERO);
    result
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut stream) => {
                    stream.recv().await;
                }
                Err(error) => {
                    tracing::warn!("failed to register SIGTERM handler: {error}");
                    std::future::pending::<()>().await;
                }
            }
        };
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result {
                    tracing::warn!("CTRL-C handler failed: {error}");
                }
            }
            _ = terminate => {}
        }
    }
    #[cfg(not(unix))]
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::warn!("CTRL-C handler failed: {error}");
    }
}

pub(crate) async fn run_server<S, R>(data_dir: Option<PathBuf>, shutdown: S, ready: R) -> Result<()>
where
    S: std::future::Future<Output = ()> + Send + 'static,
    R: FnOnce(SocketAddr) -> Result<()> + Send + 'static,
{
    if let Some(data_dir) = data_dir {
        fs::create_dir_all(&data_dir)
            .with_context(|| format!("failed to create data directory {}", data_dir.display()))?;
        std::env::set_current_dir(&data_dir)
            .with_context(|| format!("failed to use data directory {}", data_dir.display()))?;
    }

    let mut settings = load_pref();
    settings.apply_env(|key| std::env::var(key).ok());
    run_server_with_settings(settings, shutdown, ready).await
}

async fn run_server_with_settings<S, R>(settings: Settings, shutdown: S, ready: R) -> Result<()>
where
    S: std::future::Future<Output = ()> + Send + 'static,
    R: FnOnce(SocketAddr) -> Result<()> + Send + 'static,
{
    let addr: SocketAddr = format!("{}:{}", settings.listen, settings.port).parse()?;
    let state = AppState {
        settings: Arc::new(RwLock::new(settings)),
        io: FsIo::default(),
    };

    let app = Router::new()
        .route("/version", get(adapter))
        .route("/refreshrules", get(adapter))
        .route("/readconf", get(adapter))
        .route("/updateconf", post(adapter))
        .route("/flushcache", get(adapter))
        .route("/sub", get(adapter).head(adapter_head))
        .route("/sub2clashr", get(adapter))
        .route("/surge2clash", get(adapter))
        .route("/getruleset", get(adapter))
        .route("/getprofile", get(adapter))
        .route("/render", get(adapter))
        .route("/get", get(adapter))
        .route("/getlocal", get(adapter))
        .with_state(state.clone());

    let (cron_shutdown_tx, cron_shutdown_rx) = watch::channel(false);
    let cron_manager = start_cron_manager(state, cron_shutdown_rx);
    let cron_abort = cron_manager.abort_handle();

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    ready(local_addr)?;
    tracing::info!("Startup completed. Serving HTTP @ http://{}", local_addr);
    let (shutdown_started_tx, mut shutdown_started_rx) = tokio::sync::oneshot::channel();
    let graceful = async move {
        shutdown.await;
        let _ = shutdown_started_tx.send(());
    };
    let server = axum::serve(listener, app)
        .with_graceful_shutdown(graceful)
        .into_future();
    tokio::pin!(server);

    tokio::select! {
        result = &mut server => {
            let _ = cron_shutdown_tx.send(true);
            let _ = tokio::time::timeout(GRACEFUL_SHUTDOWN_LIMIT, cron_manager).await;
            result.context("HTTP server failed")
        }
        _ = &mut shutdown_started_rx => {
            tracing::info!("shutdown requested; draining HTTP and background tasks");
            let _ = cron_shutdown_tx.send(true);
            match tokio::time::timeout(GRACEFUL_SHUTDOWN_LIMIT, async {
                let (server_result, cron_result) = tokio::join!(&mut server, cron_manager);
                server_result.context("HTTP server failed")?;
                if let Err(error) = cron_result {
                    if !error.is_cancelled() {
                        return Err(error).context("cron manager failed");
                    }
                }
                Ok(())
            }).await {
                Ok(result) => result,
                Err(_) => {
                    cron_abort.abort();
                    tracing::warn!("graceful shutdown exceeded 30 seconds");
                    Ok(())
                }
            }
        }
    }
}

async fn adapter(
    State(state): State<AppState>,
    method: AxumMethod,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    call_core(state, method, uri, headers, body).await
}

async fn adapter_head(
    State(state): State<AppState>,
    method: AxumMethod,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    call_core(state, method, uri, headers, Bytes::new()).await
}

async fn call_core(
    state: AppState,
    method: AxumMethod,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let method = match method {
        AxumMethod::GET => Method::Get,
        AxumMethod::HEAD => Method::Head,
        AxumMethod::POST => Method::Post,
        _ => Method::Get,
    };
    let request = CoreRequest {
        method,
        path: uri.path().to_string(),
        query: uri.query().unwrap_or("").to_string(),
        body: String::from_utf8_lossy(&body).into_owned(),
        headers: headers
            .iter()
            .filter_map(|(key, value)| {
                Some((key.as_str().to_string(), value.to_str().ok()?.to_string()))
            })
            .collect::<BTreeMap<_, _>>(),
    };
    let mut settings = state.settings.read().await.clone();
    if settings.reload_conf_on_request {
        let mut refreshed = load_pref();
        refreshed.apply_env(|key| std::env::var(key).ok());
        settings = refreshed;
    }
    let updates_settings = matches!(request.path.as_str(), "/readconf" | "/updateconf");
    let response = handle_request(&state.io, &mut settings, request).await;
    if updates_settings && response.status < 400 {
        *state.settings.write().await = settings;
    }
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header("content-type", response.content_type);
    for (key, value) in response.headers {
        builder = builder.header(key, value);
    }
    builder
        .body(axum::body::Body::from(response.body))
        .unwrap_or_else(|_| Response::new(axum::body::Body::from("response build failed")))
}

fn load_pref() -> Settings {
    for file in ["pref.toml", "pref.yml", "pref.yaml", "pref.ini"] {
        if let Ok(content) = read_pref_file(file) {
            if let Ok(settings) = Settings::detect_and_parse(&content) {
                return settings;
            }
        }
    }
    Settings::default()
}

fn read_pref_file(path: &str) -> Result<String> {
    let content = fs::read_to_string(path)?;
    let base_dir = Path::new(path).parent().unwrap_or_else(|| Path::new(""));
    expand_imports_with(&content, |import| {
        let import_path = Path::new(import);
        let path = if import_path.is_absolute() {
            import_path.to_path_buf()
        } else {
            base_dir.join(import_path)
        };
        fs::read_to_string(&path)
            .map_err(|err| subconverter_core::Error::Io(format!("{}: {err}", path.display())))
    })
    .map_err(Into::into)
}

#[derive(Debug, Clone, Default)]
struct FsIo {
    clients: Arc<std::sync::RwLock<BTreeMap<String, reqwest::Client>>>,
    cache: Arc<std::sync::RwLock<BTreeMap<String, CacheEntry>>>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    expires_at: Instant,
    content: FetchedContent,
}

#[async_trait]
impl PlatformIo for FsIo {
    async fn fetch_url(&self, url: &str) -> subconverter_core::Result<String> {
        Ok(self.fetch(&FetchRequest::new(url)).await?.body)
    }

    async fn fetch_url_with_headers(&self, url: &str) -> subconverter_core::Result<FetchedContent> {
        self.fetch(&FetchRequest::new(url)).await
    }

    async fn fetch(&self, request: &FetchRequest) -> subconverter_core::Result<FetchedContent> {
        let mut current = reqwest::Url::parse(&request.url)
            .map_err(|err| Error::Forbidden(format!("invalid URL: {err}")))?;
        for redirect_count in 0..=request.max_redirects {
            validate_fetch_url(&current, request)?;
            let client = self.client_for(&current, request).await?;
            let mut outgoing = client.get(current.clone());
            for (key, value) in &request.headers {
                outgoing = outgoing.header(key, value);
            }
            let mut response = outgoing.send().await.map_err(map_reqwest_error)?;
            let status = response.status();
            if status.is_redirection() {
                if redirect_count == request.max_redirects {
                    return Err(Error::Upstream(format!(
                        "redirect limit exceeded for {}",
                        request.url
                    )));
                }
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| {
                        Error::Upstream(format!(
                            "redirect response from {current} has no valid Location"
                        ))
                    })?;
                current = current
                    .join(location)
                    .map_err(|err| Error::Upstream(format!("invalid redirect URL: {err}")))?;
                continue;
            }
            if let Some(length) = response.content_length() {
                if length > request.max_bytes as u64 {
                    return Err(Error::PayloadTooLarge {
                        limit: request.max_bytes,
                    });
                }
            }
            let headers = response
                .headers()
                .iter()
                .filter_map(|(key, value)| {
                    Some((key.as_str().to_string(), value.to_str().ok()?.to_string()))
                })
                .collect();
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(map_reqwest_error)? {
                if bytes.len().saturating_add(chunk.len()) > request.max_bytes {
                    return Err(Error::PayloadTooLarge {
                        limit: request.max_bytes,
                    });
                }
                bytes.extend_from_slice(&chunk);
            }
            let body = String::from_utf8(bytes)
                .map_err(|err| Error::Upstream(format!("upstream body is not UTF-8: {err}")))?;
            return Ok(FetchedContent {
                body,
                headers,
                status: status.as_u16(),
                final_url: current.to_string(),
            });
        }
        Err(Error::Upstream("redirect processing failed".to_string()))
    }

    async fn read_file(&self, path: &str) -> subconverter_core::Result<String> {
        fs::read_to_string(path).map_err(|err| subconverter_core::Error::Io(err.to_string()))
    }

    async fn write_file(
        &self,
        path: &str,
        content: &str,
        overwrite: bool,
    ) -> subconverter_core::Result<()> {
        if !overwrite && std::path::Path::new(path).exists() {
            return Err(subconverter_core::Error::Io(format!(
                "file already exists: {path}"
            )));
        }
        fs::write(path, content).map_err(|err| subconverter_core::Error::Io(err.to_string()))
    }

    async fn flush_cache(&self) -> subconverter_core::Result<()> {
        self.cache.write().expect("cache lock poisoned").clear();
        Ok(())
    }

    async fn cache_get(
        &self,
        namespace: &str,
        key: &str,
    ) -> subconverter_core::Result<Option<FetchedContent>> {
        let cache_key = format!("{namespace}\0{key}");
        let cache = self.cache.read().expect("cache lock poisoned");
        let Some(entry) = cache.get(&cache_key) else {
            return Ok(None);
        };
        if entry.expires_at <= Instant::now() {
            return Ok(None);
        }
        Ok(Some(entry.content.clone()))
    }

    async fn cache_get_stale(
        &self,
        namespace: &str,
        key: &str,
    ) -> subconverter_core::Result<Option<FetchedContent>> {
        Ok(self
            .cache
            .read()
            .expect("cache lock poisoned")
            .get(&format!("{namespace}\0{key}"))
            .map(|entry| entry.content.clone()))
    }

    async fn cache_put(
        &self,
        namespace: &str,
        key: &str,
        content: &FetchedContent,
        ttl_seconds: u64,
    ) -> subconverter_core::Result<()> {
        self.cache.write().expect("cache lock poisoned").insert(
            format!("{namespace}\0{key}"),
            CacheEntry {
                expires_at: Instant::now() + Duration::from_secs(ttl_seconds),
                content: content.clone(),
            },
        );
        Ok(())
    }

    fn capabilities(&self) -> AdapterCapabilities {
        AdapterCapabilities {
            persistent_config: true,
            cache_management: true,
            local_files: true,
            trusted_local_files: false,
            raw_fetch_routes: true,
            local_management_routes: true,
            scripts: true,
            cron: true,
            gist_upload: true,
        }
    }

    async fn upload_gist(
        &self,
        name: &str,
        path: &str,
        content: &str,
        write_managed_url: bool,
    ) -> subconverter_core::Result<()> {
        upload_gist(name, path, content, write_managed_url).await
    }
}

fn start_cron_manager(
    state: AppState,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut active = Vec::<tokio::task::JoinHandle<()>>::new();
        let mut last_tasks = None;
        loop {
            if *shutdown.borrow() {
                break;
            }
            let settings = state.settings.read().await.clone();
            let task_state = (
                settings.enable_cron,
                settings.cron_tasks.clone(),
                settings.script_memory_limit_bytes,
                settings.script_timeout_millis,
            );
            if last_tasks.as_ref() != Some(&task_state) {
                for task in active.drain(..) {
                    task.abort();
                }
                if settings.enable_cron {
                    for task in settings.cron_tasks.clone() {
                        let io = state.io.clone();
                        let task_settings = settings.clone();
                        let mut task_shutdown = shutdown.clone();
                        active.push(tokio::spawn(async move {
                            let schedule = match cron::Schedule::from_str(&task.cron_exp) {
                                Ok(schedule) => schedule,
                                Err(err) => {
                                    tracing::warn!(
                                        "cron task '{}' has invalid expression '{}': {err}",
                                        task.name,
                                        task.cron_exp
                                    );
                                    return;
                                }
                            };
                            loop {
                                let Some(next) = schedule.upcoming(chrono::Utc).next() else {
                                    return;
                                };
                                let delay = (next - chrono::Utc::now())
                                    .to_std()
                                    .unwrap_or(Duration::ZERO);
                                tokio::select! {
                                    _ = tokio::time::sleep(delay) => {}
                                    changed = task_shutdown.changed() => {
                                        if changed.is_err() || *task_shutdown.borrow() {
                                            return;
                                        }
                                        continue;
                                    }
                                }
                                let script =
                                    match load_cron_script(&io, &task_settings, &task.path).await {
                                        Ok(script) => script,
                                        Err(err) => {
                                            tracing::warn!(
                                                "cron task '{}' load failed: {err}",
                                                task.name
                                            );
                                            continue;
                                        }
                                    };
                                let execution_settings = task_settings.clone();
                                let timeout_millis = if task.timeout > 0 {
                                    (task.timeout as u64).saturating_mul(1_000)
                                } else {
                                    execution_settings.script_timeout_millis
                                };
                                let name = task.name.clone();
                                match tokio::task::spawn_blocking(move || {
                                    execute_background_script(
                                        &script,
                                        &execution_settings,
                                        timeout_millis,
                                    )
                                })
                                .await
                                {
                                    Ok(Ok(())) => {}
                                    Ok(Err(err)) => {
                                        tracing::warn!("cron task '{name}' execution failed: {err}")
                                    }
                                    Err(err) => {
                                        tracing::warn!("cron task '{name}' worker failed: {err}")
                                    }
                                }
                            }
                        }));
                    }
                }
                last_tasks = Some(task_state);
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
        for task in active {
            task.abort();
        }
    })
}

async fn load_cron_script(
    io: &FsIo,
    settings: &Settings,
    path: &str,
) -> subconverter_core::Result<String> {
    if path.starts_with("https://") || path.starts_with("http://") {
        let mut request = FetchRequest::new(path);
        request.max_bytes = settings.security.max_download_bytes;
        request.connect_timeout_seconds = settings.security.connect_timeout_seconds;
        request.request_timeout_seconds = settings.security.request_timeout_seconds;
        request.max_redirects = settings.security.max_redirects;
        request.allow_private_network = settings.security.allow_private_network;
        request.allow_plain_http = settings.security.allow_plain_http;
        let fetched = io.fetch(&request).await?;
        if !(200..300).contains(&fetched.status) {
            return Err(Error::Upstream(format!(
                "{} returned HTTP {}",
                fetched.final_url, fetched.status
            )));
        }
        return Ok(fetched.body);
    }
    validate_cron_path(path, settings)?;
    io.read_file(path).await
}

fn validate_cron_path(path: &str, settings: &Settings) -> subconverter_core::Result<()> {
    let path_value = Path::new(path);
    if path_value
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(Error::Forbidden(
            "cron script path traversal is blocked".to_string(),
        ));
    }
    if settings
        .security
        .allowed_local_roots
        .iter()
        .map(Path::new)
        .any(|root| path_value.is_absolute() == root.is_absolute() && path_value.starts_with(root))
    {
        Ok(())
    } else {
        Err(Error::Forbidden(format!(
            "cron script is outside configured roots: {path}"
        )))
    }
}

impl FsIo {
    async fn client_for(
        &self,
        url: &reqwest::Url,
        request: &FetchRequest,
    ) -> subconverter_core::Result<reqwest::Client> {
        let host = url
            .host_str()
            .ok_or_else(|| Error::Forbidden("upstream URL has no host".to_string()))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| Error::Forbidden("upstream URL has no port".to_string()))?;
        let addresses = tokio::net::lookup_host((host, port))
            .await
            .map_err(|err| Error::Upstream(format!("DNS resolution failed for {host}: {err}")))?
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            return Err(Error::Upstream(format!(
                "DNS resolution returned no addresses for {host}"
            )));
        }
        if !request.allow_private_network {
            for address in &addresses {
                if is_non_public_ip(address.ip()) {
                    return Err(Error::Forbidden(format!(
                        "DNS resolved {host} to blocked address {}",
                        address.ip()
                    )));
                }
            }
        }
        let address_key = addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let cache_key = format!(
            "{host}|{address_key}|{}|{}",
            request.connect_timeout_seconds, request.request_timeout_seconds
        );
        if let Some(client) = self
            .clients
            .read()
            .expect("client lock poisoned")
            .get(&cache_key)
            .cloned()
        {
            return Ok(client);
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(request.connect_timeout_seconds))
            .timeout(Duration::from_secs(request.request_timeout_seconds))
            .resolve_to_addrs(host, &addresses)
            .build()
            .map_err(|err| Error::Io(format!("HTTP client setup failed: {err}")))?;
        self.clients
            .write()
            .expect("client lock poisoned")
            .insert(cache_key, client.clone());
        Ok(client)
    }
}

fn map_reqwest_error(err: reqwest::Error) -> Error {
    if err.is_timeout() {
        Error::Timeout(err.to_string())
    } else {
        Error::Upstream(err.to_string())
    }
}

fn validate_fetch_url(url: &reqwest::Url, request: &FetchRequest) -> subconverter_core::Result<()> {
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
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::Forbidden(
            "credentials in upstream URLs are not allowed".to_string(),
        ));
    }
    Ok(())
}

fn is_non_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
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
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        }
        IpAddr::V6(ip) => is_non_public_ipv6(ip),
    }
}

fn is_non_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_non_public_ip(IpAddr::V4(mapped));
    }
    let segments = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || segments[0] == 0x2001 && segments[1] == 0x0db8
}

async fn upload_gist(
    name: &str,
    path: &str,
    content: &str,
    write_managed_url: bool,
) -> subconverter_core::Result<()> {
    let conf_path = Path::new("gistconf.ini");
    let conf = fs::read_to_string(conf_path)
        .map_err(|err| subconverter_core::Error::Io(format!("gistconf.ini: {err}")))?;
    let mut ini = parse_simple_ini(&conf);
    let common = ini
        .get("common")
        .ok_or_else(|| subconverter_core::Error::Io("gistconf.ini missing [common]".to_string()))?;
    let token = common.get("token").cloned().unwrap_or_default();
    if token.is_empty() {
        return Err(subconverter_core::Error::Io(
            "gistconf.ini missing [common] token".to_string(),
        ));
    }
    let mut gist_id = common.get("id").cloned().unwrap_or_default();
    let mut username = common.get("username").cloned().unwrap_or_default();
    let upload_path = if path.is_empty() {
        common
            .get("path")
            .cloned()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| name.to_string())
    } else {
        path.to_string()
    };

    let mut upload_content = content.to_string();
    let client = reqwest::Client::builder()
        .user_agent(format!("subconverter-rs/{}", subconverter_core::VERSION))
        .build()
        .map_err(|err| subconverter_core::Error::Io(err.to_string()))?;
    let response = if gist_id.is_empty() {
        client
            .post("https://api.github.com/gists")
            .bearer_auth(&token)
            .json(&gist_payload(&upload_path, &upload_content))
            .send()
            .await
    } else {
        let raw_url = gist_raw_url(&username, &gist_id, &upload_path);
        if write_managed_url {
            upload_content = format!("#!MANAGED-CONFIG {raw_url}\n{upload_content}");
        }
        client
            .patch(format!("https://api.github.com/gists/{gist_id}"))
            .bearer_auth(&token)
            .json(&gist_payload(&upload_path, &upload_content))
            .send()
            .await
    }
    .map_err(|err| subconverter_core::Error::Io(format!("gist upload failed: {err}")))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| subconverter_core::Error::Io(err.to_string()))?;
    if !status.is_success() {
        return Err(subconverter_core::Error::Io(format!(
            "gist upload failed with status {status}: {body}"
        )));
    }
    let json: serde_json::Value = serde_json::from_str(&body)
        .map_err(|err| subconverter_core::Error::Io(format!("invalid gist response: {err}")))?;
    if let Some(id) = json.get("id").and_then(serde_json::Value::as_str) {
        gist_id = id.to_string();
    }
    if let Some(login) = json
        .get("owner")
        .and_then(|owner| owner.get("login"))
        .and_then(serde_json::Value::as_str)
    {
        username = login.to_string();
    }

    let raw_url = gist_raw_url(&username, &gist_id, &upload_path);
    let common = ini.entry("common".to_string()).or_default();
    common.insert("token".to_string(), token);
    common.insert("id".to_string(), gist_id);
    common.insert("username".to_string(), username);
    let section = ini.entry(upload_path.clone()).or_default();
    section.clear();
    section.insert("type".to_string(), name.to_string());
    section.insert("url".to_string(), raw_url);
    fs::write(conf_path, write_simple_ini(&ini))
        .map_err(|err| subconverter_core::Error::Io(format!("gistconf.ini: {err}")))
}

fn gist_payload(path: &str, content: &str) -> serde_json::Value {
    serde_json::json!({
        "files": {
            path: {
                "content": content
            }
        }
    })
}

fn gist_raw_url(username: &str, gist_id: &str, path: &str) -> String {
    format!("https://gist.githubusercontent.com/{username}/{gist_id}/raw/{path}")
}

fn parse_simple_ini(content: &str) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut result: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut current = String::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('#') {
            continue;
        }
        if let Some(section) = trimmed
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        {
            current = section.trim().to_string();
            result.entry(current.clone()).or_default();
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            result
                .entry(current.clone())
                .or_default()
                .insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    result
}

fn write_simple_ini(ini: &BTreeMap<String, BTreeMap<String, String>>) -> String {
    let mut output = String::new();
    for (section, values) in ini {
        if !section.is_empty() {
            output.push('[');
            output.push_str(section);
            output.push_str("]\n");
        }
        for (key, value) in values {
            output.push_str(key);
            output.push('=');
            output.push_str(value);
            output.push('\n');
        }
        output.push('\n');
    }
    output
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn no_arguments_preserve_foreground_mode() {
        let cli = Cli::try_parse_from(["subconverter-server"]).expect("parse");
        assert!(cli.command.is_none());
    }

    #[test]
    fn service_install_parses_scope_paths_and_no_start() {
        let cli = Cli::try_parse_from([
            "subconverter-server",
            "service",
            "install",
            "--scope",
            "system",
            "--data-dir",
            "state",
            "--asset-dir",
            "release",
            "--no-start",
        ])
        .expect("parse");
        let Some(Command::Service(service::ServiceArgs {
            command: service::ServiceCommand::Install(args),
        })) = cli.command
        else {
            panic!("expected service install");
        };
        assert_eq!(args.scope, service::Scope::System);
        assert_eq!(args.data_dir, Some(PathBuf::from("state")));
        assert_eq!(args.asset_dir, Some(PathBuf::from("release")));
        assert!(args.no_start);
    }

    #[tokio::test]
    async fn cron_manager_obeys_shutdown_signal() {
        let state = AppState {
            settings: Arc::new(RwLock::new(Settings::default())),
            io: FsIo::default(),
        };
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let manager = start_cron_manager(state, shutdown_rx);
        shutdown_tx.send(true).expect("send shutdown");
        tokio::time::timeout(Duration::from_secs(1), manager)
            .await
            .expect("cron manager should stop")
            .expect("cron manager join");
    }

    #[tokio::test]
    async fn occupied_port_fails_before_reporting_ready() {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("occupy port");
        let settings = Settings {
            port: occupied.local_addr().expect("local address").port(),
            ..Settings::default()
        };
        let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ready_flag = Arc::clone(&ready);
        let result = run_server_with_settings(settings, std::future::pending(), move |_| {
            ready_flag.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
        .await;
        assert!(result.is_err());
        assert!(!ready.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn shutdown_drains_server_and_cron_manager() {
        let settings = Settings {
            port: 0,
            ..Settings::default()
        };
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            run_server_with_settings(settings, async {}, |_| Ok(())),
        )
        .await
        .expect("shutdown should finish promptly");
        result.expect("graceful shutdown");
    }
}
