use anyhow::{Context, Result};
use std::fs::File;
use std::sync::Arc;

mod config;
mod proxy;
mod router;
mod windows;

use config::ServiceSettings;
use router::SocksLocalRouter;

#[tokio::main]
async fn main() -> Result<()> {
    let driver = ndisapi::Ndisapi::new("NDISRD")
        .context("windows packet filter driver is not installed")?;
    driver
        .get_version()
        .context("windows packet filter driver is not installed")?;

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
    println!("SOCKS5 local router started. Press Ctrl+C to stop.");

    tokio::signal::ctrl_c().await.context("failed to listen for Ctrl+C")?;

    router.close()?;
    Ok(())
}
