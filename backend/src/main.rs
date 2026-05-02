use hybridcipher_secretlink_server::{build_app, SecretLinkConfig};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "hybridcipher_secretlink_server=info".into()),
        )
        .init();

    let config = SecretLinkConfig {
        database_url: std::env::var("SECRETLINK_DATABASE_URL")
            .unwrap_or_else(|_| "sqlite://secretlink.db".to_string()),
        bind_addr: std::env::var("SECRETLINK_BIND_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8787".to_string()),
        web_dev_dir: std::env::var("SECRETLINK_WEB_DEV_DIR").ok().map(Into::into),
        claim_lease: std::time::Duration::from_secs(60),
        cleanup_interval: std::time::Duration::from_secs(30),
        tombstone_retention: std::time::Duration::from_secs(60 * 60 * 24),
    };

    let app = build_app(config.clone()).await?;
    let listener = TcpListener::bind(&config.bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
