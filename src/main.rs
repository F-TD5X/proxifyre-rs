use anyhow::{Context, Result};
use std::fs::File;
use std::sync::Arc;
use std::thread;

mod config;
mod logging;
mod proxy;
mod router;
mod tui;
mod windows;

use config::ServiceSettings;
use router::SocksLocalRouter;
use tui::Tui;
use tokio::sync::oneshot;

#[tokio::main]
async fn main() -> Result<()> {
    let driver = ndisapi::Ndisapi::new("NDISRD")
        .context("windows packet filter driver is not installed")?;
    driver
        .get_version()
        .context("windows packet filter driver is not installed")?;

    let logs = Arc::new(std::sync::Mutex::new(Vec::new()));
    logging::init(Arc::clone(&logs))
        .map_err(|err| anyhow::anyhow!("failed to initialize logger: {err}"))?;
    let router = Arc::new(SocksLocalRouter::new(&driver)?);

    let config_file = File::open("config.json").context("failed to open config.json")?;
    let settings: ServiceSettings = serde_json::from_reader(config_file)
        .context("failed to parse config.json")?;

    for proxy in settings.proxies {
        let proxy_id = router.add_socks5_proxy(&proxy.endpoint)?;
        for app in proxy.app_names {
            router.associate_process_name_to_proxy(&app, proxy_id)?;
        }
    }

    router.start()?;
    log::info!("SOCKS5 local router started. Press Ctrl+C to stop.");

    let tui_state = Arc::new(tui::TuiState::new(Arc::clone(&router), Arc::clone(&logs)));
    let (tui_done_tx, tui_done_rx) = oneshot::channel();
    let tui_state_for_thread = Arc::clone(&tui_state);
    let tui_handle = thread::spawn(move || {
        let mut tui = Tui::new(tui_state_for_thread);
        let _ = tui.run();
        let _ = tui_done_tx.send(());
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            log::info!("Shutting down...");
            tui_state.request_shutdown();
        }
        _ = tui_done_rx => {}
    }

    tui_state.request_shutdown();
    let _ = tui_handle.join();

    router.close()?;
    Ok(())
}
