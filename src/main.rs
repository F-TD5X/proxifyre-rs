use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    proxifyre::app::run().await
}
