use super::CmdResult;
use crate::cmd::StringifyErr as _;
use crate::feat::{
    IpOptimizeEvent, IpOptimizeParams, IpOptimizeSummary, IpOptimizeView, clear_ip_optimize_results,
    load_ip_optimize_view, run_ip_optimize, stop_run,
};
use tauri::ipc::Channel;

/// Runs a full optimization pass for the active profile, streaming progress
/// through the channel; stops only via [`stop_ip_optimize`].
#[tauri::command]
#[specta::specta]
pub async fn start_ip_optimize(
    params: Option<IpOptimizeParams>,
    on_event: Channel<IpOptimizeEvent>,
) -> CmdResult<IpOptimizeSummary> {
    run_ip_optimize(params.unwrap_or_default(), &on_event)
        .await
        .stringify_err()
}

#[tauri::command]
#[specta::specta]
pub async fn stop_ip_optimize() -> CmdResult<()> {
    stop_run();
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub async fn get_ip_optimize_result() -> CmdResult<IpOptimizeView> {
    load_ip_optimize_view().await.stringify_err()
}

#[tauri::command]
#[specta::specta]
pub async fn clear_ip_optimize_result(uid: Option<std::string::String>) -> CmdResult<()> {
    clear_ip_optimize_results(uid).await.stringify_err()
}
