use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::oneshot;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_dispatcher;

use crate::service::WINDOWS_SERVICE_NAME;

static DATA_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, service_main);

pub fn run(data_dir: Option<PathBuf>) -> Result<()> {
    DATA_DIR
        .set(data_dir.clone())
        .map_err(|_| anyhow::anyhow!("Windows service host was initialized twice"))?;
    let log_dir = data_dir.unwrap_or_else(|| PathBuf::from(".")).join("logs");
    std::fs::create_dir_all(&log_dir)
        .with_context(|| format!("failed to create log directory {}", log_dir.display()))?;
    let appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("subconverter-server")
        .filename_suffix("log")
        .max_log_files(7)
        .build(&log_dir)
        .context("failed to initialize rolling service log")?;
    let (writer, guard) = tracing_appender::non_blocking(appender);
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(writer)
        .try_init();
    let result = service_dispatcher::start(WINDOWS_SERVICE_NAME, ffi_service_main)
        .context("failed to connect to Windows SCM dispatcher");
    drop(guard);
    result
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_service() {
        tracing::error!("Windows service failed: {error:#}");
    }
}

fn run_service() -> Result<()> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let shutdown_tx = Arc::new(Mutex::new(Some(shutdown_tx)));
    let status_slot = Arc::new(Mutex::new(None::<ServiceStatusHandle>));
    let handler_sender = Arc::clone(&shutdown_tx);
    let handler_status = Arc::clone(&status_slot);
    let event_handler = move |control| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
                if let Ok(slot) = handler_status.lock() {
                    if let Some(handle) = *slot {
                        let _ = handle.set_service_status(status(
                            ServiceState::StopPending,
                            ServiceControlAccept::empty(),
                            ServiceExitCode::NO_ERROR,
                            Duration::from_secs(30),
                        ));
                    }
                }
                if let Ok(mut sender) = handler_sender.lock() {
                    if let Some(sender) = sender.take() {
                        let _ = sender.send(());
                    }
                }
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = service_control_handler::register(WINDOWS_SERVICE_NAME, event_handler)
        .context("failed to register Windows service control handler")?;
    *status_slot
        .lock()
        .map_err(|_| anyhow::anyhow!("service status lock poisoned"))? = Some(status_handle);
    status_handle
        .set_service_status(status(
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            ServiceExitCode::NO_ERROR,
            Duration::from_secs(30),
        ))
        .context("failed to report StartPending")?;

    let data_dir = DATA_DIR.get().cloned().flatten();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create Windows service runtime")?;
    let ready_handle = status_handle;
    let result = runtime.block_on(crate::run_server(
        data_dir,
        async move {
            let _ = shutdown_rx.await;
        },
        move |_| {
            ready_handle
                .set_service_status(status(
                    ServiceState::Running,
                    ServiceControlAccept::STOP
                        | ServiceControlAccept::SHUTDOWN
                        | ServiceControlAccept::PRESHUTDOWN,
                    ServiceExitCode::NO_ERROR,
                    Duration::ZERO,
                ))
                .context("failed to report Running")
        },
    ));
    runtime.shutdown_timeout(Duration::ZERO);
    let exit_code = if result.is_ok() {
        ServiceExitCode::NO_ERROR
    } else {
        ServiceExitCode::ServiceSpecific(1)
    };
    status_handle
        .set_service_status(status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            exit_code,
            Duration::ZERO,
        ))
        .context("failed to report Stopped")?;
    result
}

fn status(
    state: ServiceState,
    accepted: ServiceControlAccept,
    exit_code: ServiceExitCode,
    wait_hint: Duration,
) -> ServiceStatus {
    ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: accepted,
        exit_code,
        checkpoint: 0,
        wait_hint,
        process_id: None,
    }
}
