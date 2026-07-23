use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use service_manager::{
    RestartPolicy, ServiceInstallCtx, ServiceLabel, ServiceLevel, ServiceManager, ServiceStartCtx,
    ServiceStopCtx, ServiceUninstallCtx,
};
#[cfg(not(windows))]
use service_manager::{ServiceStatus, ServiceStatusCtx};

#[cfg(not(target_os = "macos"))]
pub const WINDOWS_SERVICE_NAME: &str = "subconverter-rs";
#[cfg(target_os = "linux")]
pub const SYSTEMD_SERVICE_NAME: &str = "subconverter-rs.service";
#[cfg(target_os = "macos")]
pub const LAUNCHD_LABEL: &str = "com.fyuzh.subconverter-rs";
const SHUTDOWN_WAIT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Scope {
    System,
    User,
}

#[derive(Debug, Args)]
pub struct ServiceArgs {
    #[command(subcommand)]
    pub command: ServiceCommand,
}

#[derive(Debug, Subcommand)]
pub enum ServiceCommand {
    /// Install or upgrade the managed service.
    Install(InstallArgs),
    /// Start the installed service.
    Start(ScopeArgs),
    /// Stop the installed service.
    Stop(ScopeArgs),
    /// Restart the installed service.
    Restart(ScopeArgs),
    /// Print running, stopped, or not-installed.
    Status(ScopeArgs),
    /// Stop and unregister the service without deleting its data.
    Uninstall(ScopeArgs),
}

#[derive(Debug, Clone, Args)]
pub struct ScopeArgs {
    #[arg(long, value_enum, default_value_t = Scope::System)]
    pub scope: Scope,
}

#[derive(Debug, Clone, Args)]
pub struct InstallArgs {
    #[arg(long, value_enum, default_value_t = Scope::System)]
    pub scope: Scope,
    /// Persistent data directory. Defaults to the platform standard location.
    #[arg(long)]
    pub data_dir: Option<PathBuf>,
    /// Directory containing the release package's base/ directory.
    #[arg(long)]
    pub asset_dir: Option<PathBuf>,
    /// Register the service but leave it stopped.
    #[arg(long)]
    pub no_start: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusKind {
    Running,
    Stopped,
    NotInstalled,
}

impl StatusKind {
    pub fn text(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::NotInstalled => "not-installed",
        }
    }

    pub fn exit_code(self) -> u8 {
        match self {
            Self::Running => 0,
            Self::Stopped => 3,
            Self::NotInstalled => 4,
        }
    }
}

#[derive(Debug, Clone)]
struct ServicePaths {
    program: PathBuf,
    data: PathBuf,
    source_assets: PathBuf,
}

pub fn execute(args: ServiceArgs) -> Result<u8> {
    match args.command {
        ServiceCommand::Install(args) => {
            install(args)?;
            Ok(0)
        }
        ServiceCommand::Start(args) => {
            start(args.scope)?;
            Ok(0)
        }
        ServiceCommand::Stop(args) => {
            stop(args.scope)?;
            Ok(0)
        }
        ServiceCommand::Restart(args) => {
            restart(args.scope)?;
            Ok(0)
        }
        ServiceCommand::Status(args) => {
            let status = status(args.scope)?;
            println!("{}", status.text());
            Ok(status.exit_code())
        }
        ServiceCommand::Uninstall(args) => {
            uninstall(args.scope)?;
            Ok(0)
        }
    }
}

fn validate_scope(scope: Scope) -> Result<()> {
    let _ = scope;
    #[cfg(windows)]
    if scope == Scope::User {
        bail!("Windows SCM does not support --scope user; use --scope system");
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = scope;
        bail!("native service management is unsupported on this platform");
    }
    Ok(())
}

fn install(args: InstallArgs) -> Result<()> {
    validate_scope(args.scope)?;
    reject_parallel_scope(args.scope)?;
    let paths = resolve_paths(args.scope, args.data_dir, args.asset_dir)?;
    let current = status(args.scope)?;
    if current == StatusKind::Running {
        stop(args.scope)?;
    }
    if current != StatusKind::NotInstalled {
        unregister(args.scope)?;
    }

    prepare_account(args.scope, &paths.data)?;
    prepare_installation(args.scope, &paths)?;
    register(args.scope, &paths)?;

    if args.no_start {
        #[cfg(target_os = "macos")]
        {
            // launchd loads RunAtLoad jobs as part of installation.
            if status(args.scope)? == StatusKind::Running {
                stop(args.scope)?;
            }
        }
        println!(
            "installed {} service (stopped); data: {}",
            scope_name(args.scope),
            paths.data.display()
        );
    } else {
        start(args.scope)?;
        println!(
            "installed and started {} service; data: {}",
            scope_name(args.scope),
            paths.data.display()
        );
    }
    Ok(())
}

fn start(scope: Scope) -> Result<()> {
    validate_scope(scope)?;
    match status(scope)? {
        StatusKind::Running => return Ok(()),
        StatusKind::NotInstalled => bail!("service is not installed"),
        StatusKind::Stopped => {}
    }
    let manager = manager(scope)?;
    manager
        .start(ServiceStartCtx {
            label: service_label()?,
        })
        .context("failed to start service")?;
    wait_for_status(scope, StatusKind::Running, SHUTDOWN_WAIT)
}

fn stop(scope: Scope) -> Result<()> {
    validate_scope(scope)?;
    match status(scope)? {
        StatusKind::Stopped | StatusKind::NotInstalled => return Ok(()),
        StatusKind::Running => {}
    }
    let manager = manager(scope)?;
    manager
        .stop(ServiceStopCtx {
            label: service_label()?,
        })
        .context("failed to stop service")?;
    wait_for_status(scope, StatusKind::Stopped, SHUTDOWN_WAIT)
}

fn restart(scope: Scope) -> Result<()> {
    validate_scope(scope)?;
    if status(scope)? == StatusKind::NotInstalled {
        bail!("service is not installed");
    }
    stop(scope)?;
    start(scope)
}

fn uninstall(scope: Scope) -> Result<()> {
    validate_scope(scope)?;
    if status(scope)? == StatusKind::Running {
        stop(scope)?;
    }
    if definition_path(scope)?.exists() || status(scope)? != StatusKind::NotInstalled {
        unregister(scope)?;
    }
    println!("uninstalled service; managed program and data were preserved");
    Ok(())
}

fn unregister(scope: Scope) -> Result<()> {
    let manager = manager(scope)?;
    manager
        .uninstall(ServiceUninstallCtx {
            label: service_label()?,
        })
        .context("failed to unregister service")?;
    #[cfg(target_os = "linux")]
    reload_systemd(scope)?;
    Ok(())
}

fn status(scope: Scope) -> Result<StatusKind> {
    validate_scope(scope)?;
    #[cfg(windows)]
    {
        let _ = scope;
        windows_status()
    }
    #[cfg(not(windows))]
    {
        let manager = manager(scope)?;
        let status = manager
            .status(ServiceStatusCtx {
                label: service_label()?,
            })
            .context("failed to query service status")?;
        Ok(match status {
            ServiceStatus::Running => StatusKind::Running,
            ServiceStatus::Stopped(_) => StatusKind::Stopped,
            ServiceStatus::NotInstalled if definition_path(scope)?.exists() => StatusKind::Stopped,
            ServiceStatus::NotInstalled => StatusKind::NotInstalled,
        })
    }
}

#[cfg(windows)]
fn windows_status() -> Result<StatusKind> {
    let output = Command::new("sc.exe")
        .args(["query", WINDOWS_SERVICE_NAME])
        .output()
        .context("failed to query Windows service")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        if output.status.code() == Some(1060) || stdout.contains("1060") || stderr.contains("1060")
        {
            return Ok(StatusKind::NotInstalled);
        }
        bail!(
            "failed to query Windows service (exit {}): {}",
            output.status,
            if stderr.trim().is_empty() {
                stdout.trim()
            } else {
                stderr.trim()
            }
        );
    }
    let state = stdout.lines().find_map(|line| {
        let (_, value) = line.split_once(':')?;
        let value = value.split_whitespace().next()?.parse::<u32>().ok()?;
        (1..=7).contains(&value).then_some(value)
    });
    match state {
        Some(1) | Some(2) => Ok(StatusKind::Stopped),
        Some(3) | Some(4) | Some(5) | Some(6) | Some(7) => Ok(StatusKind::Running),
        Some(value) => bail!("Windows SCM returned unknown service state {value}"),
        None => bail!("Windows SCM response did not contain a service state"),
    }
}

fn wait_for_status(scope: Scope, expected: StatusKind, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let actual = status(scope)?;
        if actual == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "service did not reach {} within {} seconds (current: {})",
                expected.text(),
                timeout.as_secs(),
                actual.text()
            );
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn register(scope: Scope, paths: &ServicePaths) -> Result<()> {
    let mut manager = manager(scope)?;
    manager
        .set_level(match scope {
            Scope::System => ServiceLevel::System,
            Scope::User => ServiceLevel::User,
        })
        .context("failed to select service scope")?;

    let (args, contents, username) = service_definition(scope, paths)?;
    manager
        .install(ServiceInstallCtx {
            label: service_label()?,
            program: paths.program.clone(),
            args,
            contents: Some(contents).filter(|value| !value.is_empty()),
            username,
            working_directory: Some(paths.data.clone()),
            environment: None,
            autostart: true,
            restart_policy: RestartPolicy::OnFailure {
                delay_secs: Some(5),
                max_retries: None,
                reset_after_secs: Some(86_400),
            },
        })
        .context("failed to register service")?;

    #[cfg(windows)]
    if let Err(error) = configure_windows_service() {
        let _ = manager.uninstall(ServiceUninstallCtx {
            label: service_label()?,
        });
        return Err(error);
    }
    #[cfg(target_os = "linux")]
    if let Err(error) = reload_systemd(scope) {
        let _ = manager.uninstall(ServiceUninstallCtx {
            label: service_label()?,
        });
        let _ = reload_systemd(scope);
        return Err(error);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn reload_systemd(scope: Scope) -> Result<()> {
    let mut command = Command::new("systemctl");
    if scope == Scope::User {
        command.arg("--user");
    }
    command.arg("daemon-reload");
    run_checked(&mut command, "reload systemd service definitions")
}

fn manager(scope: Scope) -> Result<Box<dyn ServiceManager>> {
    #[cfg(windows)]
    {
        let _ = scope;
        return Ok(Box::new(service_manager::ScServiceManager::default()));
    }
    #[cfg(target_os = "linux")]
    {
        return Ok(match scope {
            Scope::System => Box::new(service_manager::SystemdServiceManager::system()),
            Scope::User => Box::new(service_manager::SystemdServiceManager::user()),
        });
    }
    #[cfg(target_os = "macos")]
    {
        return Ok(match scope {
            Scope::System => Box::new(service_manager::LaunchdServiceManager::system()),
            Scope::User => Box::new(service_manager::LaunchdServiceManager::user()),
        });
    }
    #[allow(unreachable_code)]
    Err(anyhow!("native service management is unsupported"))
}

fn service_label() -> Result<ServiceLabel> {
    #[cfg(target_os = "macos")]
    let value = LAUNCHD_LABEL;
    #[cfg(not(target_os = "macos"))]
    let value = WINDOWS_SERVICE_NAME;
    ServiceLabel::from_str(value).context("invalid service label")
}

fn service_definition(
    scope: Scope,
    paths: &ServicePaths,
) -> Result<(Vec<OsString>, String, Option<String>)> {
    #[cfg(windows)]
    {
        let _ = scope;
        let args = vec![
            OsString::from("service-run"),
            OsString::from("--data-dir"),
            paths.data.as_os_str().to_owned(),
        ];
        return Ok((args, String::new(), Some("LocalService".to_string())));
    }
    #[cfg(target_os = "linux")]
    {
        let args = vec![
            OsString::from("serve"),
            OsString::from("--data-dir"),
            paths.data.as_os_str().to_owned(),
        ];
        let unit = systemd_unit(scope, &paths.program, &paths.data);
        let username = (scope == Scope::System).then(|| "subconverter".to_string());
        return Ok((args, unit, username));
    }
    #[cfg(target_os = "macos")]
    {
        let args = vec![
            OsString::from("serve"),
            OsString::from("--data-dir"),
            paths.data.as_os_str().to_owned(),
        ];
        let plist = launchd_plist(scope, &paths.program, &paths.data);
        let username = (scope == Scope::System).then(|| "_subconverter".to_string());
        return Ok((args, plist, username));
    }
    #[allow(unreachable_code)]
    Err(anyhow!("service definitions are unsupported"))
}

fn resolve_paths(
    scope: Scope,
    data_override: Option<PathBuf>,
    asset_override: Option<PathBuf>,
) -> Result<ServicePaths> {
    validate_scope(scope)?;
    let data = match data_override {
        Some(path) => absolute(path)?,
        None => default_data_dir(scope)?,
    };
    let program = default_program_path(scope, &data)?;
    let source_assets = match asset_override {
        Some(path) => absolute(path)?,
        None => discover_assets()?,
    };
    if !source_assets.join("base").is_dir() {
        bail!(
            "asset directory must contain base/: {}",
            source_assets.display()
        );
    }
    Ok(ServicePaths {
        program,
        data,
        source_assets,
    })
}

fn default_data_dir(scope: Scope) -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let _ = scope;
        let root = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        return Ok(root.join("subconverter-rs"));
    }
    #[cfg(target_os = "linux")]
    {
        return match scope {
            Scope::System => Ok(PathBuf::from("/var/lib/subconverter-rs")),
            Scope::User => {
                if let Some(path) = std::env::var_os("XDG_DATA_HOME") {
                    Ok(PathBuf::from(path).join("subconverter-rs"))
                } else {
                    Ok(home_dir()?.join(".local/share/subconverter-rs"))
                }
            }
        };
    }
    #[cfg(target_os = "macos")]
    {
        return match scope {
            Scope::System => Ok(PathBuf::from(
                "/Library/Application Support/subconverter-rs",
            )),
            Scope::User => Ok(home_dir()?.join("Library/Application Support/subconverter-rs")),
        };
    }
    #[allow(unreachable_code)]
    Err(anyhow!("default data directory is unsupported"))
}

fn default_program_path(scope: Scope, data: &Path) -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let _ = (scope, data);
        let root = std::env::var_os("ProgramFiles")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
        return Ok(root.join("subconverter-rs/subconverter-server.exe"));
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        return Ok(match scope {
            Scope::System => PathBuf::from("/usr/local/bin/subconverter-server"),
            Scope::User => data.join("bin/subconverter-server"),
        });
    }
    #[allow(unreachable_code)]
    Err(anyhow!("default program path is unsupported"))
}

fn discover_assets() -> Result<PathBuf> {
    let executable = std::env::current_exe().context("cannot locate current executable")?;
    if let Some(parent) = executable.parent() {
        if parent.join("base").is_dir() {
            return Ok(parent.to_path_buf());
        }
    }
    let current = std::env::current_dir().context("cannot read current directory")?;
    if current.join("base").is_dir() {
        return Ok(current);
    }
    bail!("cannot find release assets; pass --asset-dir containing base/")
}

fn prepare_installation(scope: Scope, paths: &ServicePaths) -> Result<()> {
    fs::create_dir_all(&paths.data)
        .with_context(|| format!("failed to create {}", paths.data.display()))?;
    fs::create_dir_all(paths.data.join("profiles"))?;
    fs::create_dir_all(paths.data.join("scripts"))?;
    fs::create_dir_all(paths.data.join("logs"))?;

    let program_dir = paths
        .program
        .parent()
        .ok_or_else(|| anyhow!("program path has no parent"))?;
    fs::create_dir_all(program_dir)
        .with_context(|| format!("failed to create {}", program_dir.display()))?;
    replace_file(&std::env::current_exe()?, &paths.program)?;
    replace_tree(&paths.source_assets.join("base"), &paths.data.join("base"))?;
    create_initial_pref(&paths.data)?;
    apply_permissions(scope, paths)
}

fn replace_file(source: &Path, destination: &Path) -> Result<()> {
    if source == destination {
        return Ok(());
    }
    let staged = destination.with_extension("new");
    let backup = destination.with_extension("old");
    if staged.exists() {
        fs::remove_file(&staged)?;
    }
    fs::copy(source, &staged).with_context(|| {
        format!(
            "failed to stage program {} -> {}",
            source.display(),
            staged.display()
        )
    })?;
    if backup.exists() {
        fs::remove_file(&backup)?;
    }
    if destination.exists() {
        fs::rename(destination, &backup)?;
    }
    if let Err(error) = fs::rename(&staged, destination) {
        if backup.exists() && !destination.exists() {
            let _ = fs::rename(&backup, destination);
        }
        return Err(error).context("failed to atomically replace managed program");
    }
    if backup.exists() {
        let _ = fs::remove_file(backup);
    }
    Ok(())
}

fn replace_tree(source: &Path, destination: &Path) -> Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow!("base destination has no parent"))?;
    let staged = parent.join(".base.new");
    let backup = parent.join(".base.old");
    remove_path_if_exists(&staged)?;
    remove_path_if_exists(&backup)?;
    copy_tree(source, &staged)?;
    if destination.exists() {
        fs::rename(destination, &backup)?;
    }
    if let Err(error) = fs::rename(&staged, destination) {
        if backup.exists() && !destination.exists() {
            let _ = fs::rename(&backup, destination);
        }
        return Err(error).context("failed to atomically replace base assets");
    }
    remove_path_if_exists(&backup)?;
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let target = destination.join(entry.file_name());
        if file_type.is_symlink() {
            bail!(
                "release base/ must not contain symlinks: {}",
                entry.path().display()
            );
        }
        if file_type.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if file_type.is_file() {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn remove_path_if_exists(path: &Path) -> Result<()> {
    if path.is_dir() {
        fs::remove_dir_all(path)?;
    } else if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn create_initial_pref(data: &Path) -> Result<()> {
    if ["pref.toml", "pref.yml", "pref.yaml", "pref.ini"]
        .iter()
        .any(|name| data.join(name).exists())
    {
        return Ok(());
    }
    let content = concat!(
        "# Created by `subconverter-server service install`.\n",
        "[common]\n",
        "api_mode = true\n",
        "api_access_token = \"\"\n",
        "base_path = \"base\"\n",
        "\n",
        "[server]\n",
        "listen = \"127.0.0.1\"\n",
        "port = 25500\n",
        "\n",
        "[security]\n",
        "upstream_user_agent = \"\"\n",
    );
    fs::write(data.join("pref.toml"), content).context("failed to create initial pref.toml")
}

fn reject_parallel_scope(scope: Scope) -> Result<()> {
    #[cfg(windows)]
    let _ = scope;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let other = match scope {
            Scope::System => Scope::User,
            Scope::User => Scope::System,
        };
        if definition_path(other)?.exists() {
            bail!(
                "{} service is already installed; uninstall it before installing {} scope",
                scope_name(other),
                scope_name(scope)
            );
        }
    }
    Ok(())
}

fn definition_path(scope: Scope) -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let _ = scope;
        // The SCM has no definition file. This sentinel can never exist.
        return Ok(PathBuf::from(r"\\?\NUL\subconverter-rs"));
    }
    #[cfg(target_os = "linux")]
    {
        return Ok(match scope {
            Scope::System => PathBuf::from("/etc/systemd/system").join(SYSTEMD_SERVICE_NAME),
            Scope::User => config_home()?
                .join("systemd/user")
                .join(SYSTEMD_SERVICE_NAME),
        });
    }
    #[cfg(target_os = "macos")]
    {
        let file = format!("{LAUNCHD_LABEL}.plist");
        return Ok(match scope {
            Scope::System => PathBuf::from("/Library/LaunchDaemons").join(file),
            Scope::User => home_dir()?.join("Library/LaunchAgents").join(file),
        });
    }
    #[allow(unreachable_code)]
    Err(anyhow!("service definition path is unsupported"))
}

fn absolute(path: PathBuf) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME is not set"))
}

#[cfg(target_os = "linux")]
fn config_home() -> Result<PathBuf> {
    Ok(std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or(home_dir()?.join(".config")))
}

fn scope_name(scope: Scope) -> &'static str {
    match scope {
        Scope::System => "system",
        Scope::User => "user",
    }
}

#[cfg(target_os = "linux")]
fn systemd_unit(scope: Scope, program: &Path, data: &Path) -> String {
    let program_argument = systemd_exec_quote(program);
    let data_argument = systemd_exec_quote(data);
    let data_directive = systemd_directive_path(data);
    let user = if scope == Scope::System {
        "User=subconverter\nGroup=subconverter\n"
    } else {
        ""
    };
    let hardening = if scope == Scope::System {
        "NoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=read-only\n"
    } else {
        "NoNewPrivileges=true\nPrivateTmp=true\n"
    };
    format!(
        "[Unit]\nDescription=subconverter-rs subscription conversion service\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=simple\n{user}WorkingDirectory={data_directive}\nExecStart={program_argument} serve --data-dir {data_argument}\nRestart=on-failure\nRestartSec=5\nTimeoutStopSec=30\nKillSignal=SIGTERM\nUMask=0077\n{hardening}ReadWritePaths={data_directive}\n\n[Install]\nWantedBy={}\n",
        if scope == Scope::System {
            "multi-user.target"
        } else {
            "default.target"
        }
    )
}

#[cfg(target_os = "linux")]
fn systemd_exec_quote(path: &Path) -> String {
    format!(
        "\"{}\"",
        path.to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    )
}

#[cfg(target_os = "linux")]
fn systemd_directive_path(path: &Path) -> String {
    let mut escaped = String::new();
    for character in path.to_string_lossy().chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\x22"),
            '\'' => escaped.push_str("\\x27"),
            '%' => escaped.push_str("%%"),
            value if value.is_ascii_whitespace() || value.is_ascii_control() => {
                escaped.push_str(&format!("\\x{:02x}", value as u32));
            }
            value => escaped.push(value),
        }
    }
    escaped
}

#[cfg(target_os = "macos")]
fn launchd_plist(scope: Scope, program: &Path, data: &Path) -> String {
    let log_dir = data.join("logs");
    let user = if scope == Scope::System {
        "<key>UserName</key><string>_subconverter</string>"
    } else {
        ""
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{label}</string>
<key>ProgramArguments</key><array>
<string>{program}</string><string>serve</string><string>--data-dir</string><string>{data}</string>
</array>
<key>WorkingDirectory</key><string>{data}</string>
{user}
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ProcessType</key><string>Background</string>
<key>StandardOutPath</key><string>{stdout}</string>
<key>StandardErrorPath</key><string>{stderr}</string>
</dict></plist>
"#,
        label = LAUNCHD_LABEL,
        program = xml_escape(&program.to_string_lossy()),
        data = xml_escape(&data.to_string_lossy()),
        stdout = xml_escape(
            &log_dir
                .join("subconverter-server.out.log")
                .to_string_lossy()
        ),
        stderr = xml_escape(
            &log_dir
                .join("subconverter-server.err.log")
                .to_string_lossy()
        ),
    )
}

#[cfg(target_os = "macos")]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(windows)]
fn configure_windows_service() -> Result<()> {
    run_checked(
        Command::new("sc.exe").args([
            "config",
            WINDOWS_SERVICE_NAME,
            "obj=",
            r"NT AUTHORITY\LocalService",
            "password=",
            "",
        ]),
        "configure Windows service account",
    )?;
    run_checked(
        Command::new("sc.exe").args([
            "failure",
            WINDOWS_SERVICE_NAME,
            "reset=",
            "86400",
            "actions=",
            "restart/5000/restart/5000/restart/5000",
        ]),
        "configure Windows service recovery",
    )?;
    run_checked(
        Command::new("sc.exe").args(["failureflag", WINDOWS_SERVICE_NAME, "1"]),
        "configure Windows failure actions",
    )
}

fn prepare_account(scope: Scope, data: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    if scope == Scope::System && !command_succeeds(Command::new("id").args(["-u", "subconverter"]))
    {
        run_checked(
            Command::new("useradd").args([
                "--system",
                "--user-group",
                "--home-dir",
                &data.to_string_lossy(),
                "--shell",
                "/usr/sbin/nologin",
                "subconverter",
            ]),
            "create Linux service account",
        )?;
    }
    #[cfg(target_os = "macos")]
    if scope == Scope::System {
        ensure_macos_account(data)?;
    }
    #[cfg(windows)]
    {
        let _ = (scope, data);
    }
    Ok(())
}

fn apply_permissions(scope: Scope, paths: &ServicePaths) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&paths.program, fs::Permissions::from_mode(0o755))?;
        fs::set_permissions(&paths.data, fs::Permissions::from_mode(0o700))?;
        if scope == Scope::System {
            #[cfg(target_os = "linux")]
            let account = "subconverter:subconverter";
            #[cfg(target_os = "macos")]
            let account = "_subconverter:_subconverter";
            run_checked(
                Command::new("chown").args(["-R", account, &paths.data.to_string_lossy()]),
                "set data ownership",
            )?;
            #[cfg(target_os = "linux")]
            let base_owner = "root:root";
            #[cfg(target_os = "macos")]
            let base_owner = "root:wheel";
            run_checked(
                Command::new("chown").args([
                    "-R",
                    base_owner,
                    &paths.data.join("base").to_string_lossy(),
                ]),
                "set base ownership",
            )?;
            run_checked(
                Command::new("chmod").args([
                    "-R",
                    "a-w",
                    &paths.data.join("base").to_string_lossy(),
                ]),
                "make base assets read-only",
            )?;
        }
    }
    #[cfg(windows)]
    {
        let _ = scope;
        run_checked(
            Command::new("icacls").args([
                &paths.data.to_string_lossy(),
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-32-544:(OI)(CI)F",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-19:(OI)(CI)M",
                "/T",
                "/C",
            ]),
            "protect service data directory",
        )?;
        let program_dir = paths.program.parent().unwrap_or(&paths.program);
        run_checked(
            Command::new("icacls").args([
                &program_dir.to_string_lossy(),
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-32-544:(OI)(CI)F",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-19:(OI)(CI)RX",
                "/T",
                "/C",
            ]),
            "protect service program directory",
        )?;
        run_checked(
            Command::new("icacls").args([
                &paths.data.join("base").to_string_lossy(),
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-32-544:(OI)(CI)F",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-19:(OI)(CI)RX",
                "/T",
                "/C",
            ]),
            "make managed base assets read-only",
        )?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn ensure_macos_account(data: &Path) -> Result<()> {
    if command_succeeds(Command::new("id").args(["-u", "_subconverter"])) {
        return Ok(());
    }
    if command_has_output(Command::new("dscl").args([
        ".",
        "-read",
        "/Groups/_subconverter",
        "PrimaryGroupID",
    ])) {
        bail!(
            "macOS group _subconverter already exists without a matching user; inspect it before installation"
        );
    }
    let id = (300..500)
        .find(|id| {
            !command_has_output(Command::new("dscl").args([
                ".",
                "-search",
                "/Users",
                "UniqueID",
                &id.to_string(),
            ])) && !command_has_output(Command::new("dscl").args([
                ".",
                "-search",
                "/Groups",
                "PrimaryGroupID",
                &id.to_string(),
            ]))
        })
        .ok_or_else(|| anyhow!("no free macOS service UID in 300..499"))?;
    run_checked(
        Command::new("dscl").args([".", "-create", "/Groups/_subconverter"]),
        "create macOS service group",
    )?;
    run_checked(
        Command::new("dscl").args([
            ".",
            "-create",
            "/Groups/_subconverter",
            "PrimaryGroupID",
            &id.to_string(),
        ]),
        "set macOS service group ID",
    )?;
    for (key, value) in [
        ("UniqueID", id.to_string()),
        ("PrimaryGroupID", id.to_string()),
        ("UserShell", "/usr/bin/false".to_string()),
        ("NFSHomeDirectory", data.to_string_lossy().into_owned()),
        ("RealName", "subconverter-rs service".to_string()),
    ] {
        run_checked(
            Command::new("dscl").args([".", "-create", "/Users/_subconverter", key, &value]),
            "configure macOS service account",
        )?;
    }
    Ok(())
}

fn run_checked(command: &mut Command, action: &str) -> Result<()> {
    let output = command
        .output()
        .with_context(|| format!("failed to {action}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    bail!(
        "failed to {action} (exit {}): {}",
        output.status,
        if stderr.is_empty() {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        } else {
            stderr
        }
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn command_succeeds(command: &mut Command) -> bool {
    command.output().is_ok_and(|output| output.status.success())
}

#[cfg(target_os = "macos")]
fn command_has_output(command: &mut Command) -> bool {
    command
        .output()
        .is_ok_and(|output| output.status.success() && !output.stdout.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_exit_codes_are_stable() {
        assert_eq!(StatusKind::Running.exit_code(), 0);
        assert_eq!(StatusKind::Stopped.exit_code(), 3);
        assert_eq!(StatusKind::NotInstalled.exit_code(), 4);
        assert_eq!(StatusKind::NotInstalled.text(), "not-installed");
    }

    #[test]
    fn initial_pref_is_secure_and_preserved() {
        let temp = tempfile::tempdir().expect("tempdir");
        create_initial_pref(temp.path()).expect("create pref");
        let pref = fs::read_to_string(temp.path().join("pref.toml")).expect("read pref");
        assert!(pref.contains("api_mode = true"));
        assert!(pref.contains("listen = \"127.0.0.1\""));
        assert!(pref.contains("upstream_user_agent = \"\""));
        let parsed = subconverter_core::Settings::detect_and_parse(&pref).expect("parse pref");
        assert!(parsed.api_mode);
        assert_eq!(parsed.listen, "127.0.0.1");
        assert_eq!(parsed.port, 25500);
        assert!(parsed.api_access_token.is_empty());
        assert!(parsed.security.upstream_user_agent.is_empty());
        fs::write(temp.path().join("pref.toml"), "custom = true\n").expect("customize");
        create_initial_pref(temp.path()).expect("preserve pref");
        assert_eq!(
            fs::read_to_string(temp.path().join("pref.toml")).expect("read custom"),
            "custom = true\n"
        );
    }

    #[test]
    fn base_upgrade_preserves_other_data() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        fs::create_dir_all(source.join("nested")).expect("source");
        fs::create_dir_all(data.join("base")).expect("old base");
        fs::create_dir_all(data.join("profiles")).expect("profiles");
        fs::write(source.join("nested/new.txt"), "new").expect("new asset");
        fs::write(data.join("base/old.txt"), "old").expect("old asset");
        fs::write(data.join("profiles/user.ini"), "user").expect("user data");

        replace_tree(&source, &data.join("base")).expect("replace base");

        assert_eq!(
            fs::read_to_string(data.join("base/nested/new.txt")).expect("new asset"),
            "new"
        );
        assert!(!data.join("base/old.txt").exists());
        assert_eq!(
            fs::read_to_string(data.join("profiles/user.ini")).expect("user data"),
            "user"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_defaults_and_scm_entrypoint_are_stable() {
        let data = default_data_dir(Scope::System).expect("data path");
        assert!(data.ends_with("subconverter-rs"));
        let program = default_program_path(Scope::System, &data).expect("program path");
        assert!(program.ends_with("subconverter-rs/subconverter-server.exe"));
        let paths = ServicePaths {
            program,
            data: data.clone(),
            source_assets: PathBuf::new(),
        };
        let (args, contents, username) =
            service_definition(Scope::System, &paths).expect("definition");
        assert_eq!(args[0], "service-run");
        assert_eq!(args[1], "--data-dir");
        assert_eq!(args[2], data.as_os_str());
        assert!(contents.is_empty());
        assert_eq!(username.as_deref(), Some("LocalService"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn systemd_definitions_distinguish_scopes() {
        let system = systemd_unit(
            Scope::System,
            Path::new("/usr/local/bin/subconverter-server"),
            Path::new("/var/lib/subconverter-rs"),
        );
        assert!(system.contains("User=subconverter"));
        assert!(system.contains("WantedBy=multi-user.target"));
        assert!(system.contains("TimeoutStopSec=30"));
        let user = systemd_unit(
            Scope::User,
            Path::new("/home/test/.local/share/subconverter-rs/bin/subconverter-server"),
            Path::new("/home/test/.local/share/subconverter-rs"),
        );
        assert!(!user.contains("User=subconverter"));
        assert!(user.contains("WantedBy=default.target"));
        let spaced = systemd_unit(
            Scope::User,
            Path::new("/home/test/My Apps/subconverter-server"),
            Path::new("/home/test/My State/subconverter-rs"),
        );
        assert!(spaced.contains("WorkingDirectory=/home/test/My\\x20State/subconverter-rs"));
        assert!(spaced.contains(
            "ExecStart=\"/home/test/My Apps/subconverter-server\" serve --data-dir \"/home/test/My State/subconverter-rs\""
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launchd_definition_uses_fixed_label_and_logs() {
        let data = Path::new("/Library/Application Support/subconverter-rs");
        let plist = launchd_plist(
            Scope::System,
            Path::new("/usr/local/bin/subconverter-server"),
            data,
        );
        assert!(plist.contains("<string>com.fyuzh.subconverter-rs</string>"));
        assert!(plist.contains("<string>_subconverter</string>"));
        assert!(plist.contains("subconverter-server.out.log"));
        assert!(plist.contains("subconverter-server.err.log"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_rejects_user_scope() {
        assert!(validate_scope(Scope::User)
            .expect_err("user scope must fail")
            .to_string()
            .contains("does not support"));
    }
}
