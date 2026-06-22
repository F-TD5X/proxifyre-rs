use crate::config::ServiceSettings;
use crate::router::SocksLocalRouter;
use crate::tui::Tui;
use crate::windows::stats::WindowsSystemStats;
use anyhow::{Context, Result};
use std::collections::VecDeque;
use std::fs;
use std::sync::Arc;
use std::thread;
use tokio::sync::oneshot;
use tokio::task::LocalSet;

pub async fn run() -> Result<()> {
    let local = LocalSet::new();
    local
        .run_until(async {
            let logs = Arc::new(std::sync::Mutex::new(VecDeque::new()));
            crate::logging::init(Arc::clone(&logs))
                .map_err(|err| anyhow::anyhow!("failed to initialize logger: {err}"))?;
            log::info!("Starting...");
            let driver = ndisapi::Ndisapi::new("NDISRD")
                .context("windows packet filter driver is not installed")?;
            driver
                .get_version()
                .context("windows packet filter driver is not installed")?;

            let router = Arc::new(SocksLocalRouter::new(&driver)?);

            let stats = Arc::new(WindowsSystemStats::new());
            let tui_state = Arc::new(crate::tui::TuiState::new(
                Arc::clone(&router),
                Arc::clone(&logs),
                stats,
            ));
            let stats_task = tui_state.start_stats_task();

            let (tui_done_tx, tui_done_rx) = oneshot::channel();
            let tui_state_for_thread = Arc::clone(&tui_state);
            let tui_handle = thread::spawn(move || {
                let mut tui = Tui::new(tui_state_for_thread);
                let _ = tui.run();
                let _ = tui_done_tx.send(());
            });

            let start_result = async {
                let config_content =
                    fs::read_to_string("config.toml").context("failed to open config.toml")?;
                let settings: ServiceSettings =
                    toml::from_str(&config_content).context("failed to parse config.toml")?;

                for proxy in settings.proxies {
                    let proxy_id = router.add_socks5_proxy(&proxy.endpoint)?;
                    for app in proxy.app_names {
                        router.associate_process_name_to_proxy(&app, proxy_id)?;
                    }
                }

                router.start().await?;
                log::info!("SOCKS5 local router started. Press Ctrl+C to stop.");
                Ok(())
            }
            .await;

            if let Err(err) = start_result {
                tui_state.request_shutdown();
                let _ = tui_handle.join();
                let _ = stats_task.await;
                return Err(err);
            }

            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    log::info!("Shutting down...");
                    tui_state.request_shutdown();
                }
                _ = tui_done_rx => {}
            }

            tui_state.request_shutdown();
            let _ = tui_handle.join();
            let _ = stats_task.await;

            crate::logging::flush();
            router.close().await?;
            Ok(())
        })
        .await
}
