use std::{
    env, fs,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

use clap::Parser;
use panar::{Listener, State};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let builder = tracing_subscriber::registry().with(
        tracing_subscriber::EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy(),
    );

    match env::var("JOURNAL_STREAM") {
        Ok(_) => {
            builder
                .with(
                    tracing_subscriber::fmt::layer()
                        .without_time()
                        .with_target(false),
                )
                .init();
        }
        Err(_) => {
            builder
                .with(tracing_subscriber::fmt::layer().with_target(false))
                .init();
        }
    }

    let options = Options::parse();
    let config = fs::read_to_string(&options.config)?;
    let state = State::new(
        toml::from_str(&config)?,
        options.config.parent().unwrap_or_else(|| Path::new("")),
    )?;

    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, options.port));
    let listener = Listener::new(addr, state).await?;
    tokio::spawn(listener.run()).await?;
    Ok(())
}

#[derive(Debug, Parser)]
struct Options {
    #[clap(short, long, default_value = "8765")]
    port: u16,
    #[clap(short, long, default_value = "/etc/panar/config.toml")]
    config: PathBuf,
}
