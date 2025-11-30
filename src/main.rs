use std::{
    env, fs,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use clap::Parser;
use miltr_server::Server;
use panar::ArcMilter;
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{debug, error, info, level_filters::LevelFilter};
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
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, options.port));
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "listening");

    let config = fs::read_to_string(&options.config)?;
    let mut milter = ArcMilter::new(toml::from_str(&config)?)?;
    let mut server = Server::default_postfix(&mut milter);

    loop {
        let (stream, addr) = listener.accept().await?;
        debug!("accepted connection from {addr}");
        if let Err(error) = server.handle_connection(stream.compat()).await {
            error!(%addr, %error, "milter error");
        }
    }
}

#[derive(Debug, Parser)]
struct Options {
    #[clap(short, long, default_value = "8765")]
    port: u16,
    #[clap(short, long, default_value = "/etc/panar/config.toml")]
    config: PathBuf,
}
