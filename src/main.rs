use std::{
    collections::HashMap,
    env, fs,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use clap::Parser;
use mail_auth::{
    arc::ArcSealer,
    common::{
        crypto::{RsaKey, Sha256},
        headers::HeaderWriter,
    },
    dkim::Done,
    ArcOutput, AuthenticatedMessage, AuthenticationResults,
};
use miltr_common::{
    actions::{Action, Continue},
    commands::{Body, Connect, Header, Helo, Mail, Recipient},
    modifications::{headers::AddHeader, ModificationResponse},
    optneg::{Capability, OptNeg, Protocol},
};
use miltr_server::{Milter, Server};
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{debug, error, info, level_filters::LevelFilter, warn};
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

#[derive(Debug, Deserialize)]
struct Config {
    keys: HashMap<String, HashMap<String, PathBuf>>,
}

struct ArcMilter {
    domain: Option<String>,
    message: Vec<u8>,
    sealers: HashMap<String, HashMap<String, ArcSealer<RsaKey<Sha256>, Done>>>,
}

impl ArcMilter {
    fn new(config: Config) -> anyhow::Result<Self> {
        let mut sealers = HashMap::new();
        for (domain, selectors) in config.keys {
            let inner = sealers.entry(domain.clone()).or_insert_with(HashMap::new);
            for (selector, path) in selectors {
                let pem = fs::read_to_string(&path).map_err(|e| {
                    anyhow::Error::msg(format!("failed to read key file {path:?}: {e}"))
                })?;

                let key = RsaKey::<Sha256>::from_pkcs8_pem(&pem).map_err(|e| {
                    anyhow::Error::msg(format!("failed to parse key file {path:?}: {e}"))
                })?;

                let sealer = ArcSealer::from_key(key)
                    .domain(&domain)
                    .selector(&selector)
                    .headers(["From", "To", "Subject", "Date"]);

                info!(%domain, %selector, path = %path.display(), "loaded key");
                inner.insert(selector, sealer);
            }
        }

        Ok(Self {
            domain: None,
            message: Vec::with_capacity(1024),
            sealers,
        })
    }

    fn reset(&mut self) {
        self.domain = None;
        self.message.clear();
    }
}

#[async_trait::async_trait]
impl Milter for ArcMilter {
    type Error = anyhow::Error;

    async fn option_negotiation(
        &mut self,
        theirs: OptNeg,
    ) -> Result<OptNeg, miltr_server::Error<Self::Error>> {
        debug!(
            version = theirs.version,
            capabilities = ?theirs.capabilities,
            protocol = ?theirs.protocol,
            macro_stages = ?theirs.macro_stages,
            "option negotiation received"
        );

        let mut capabilities = Capability::empty();
        capabilities.insert(Capability::SMFIF_ADDHDRS);
        let out = OptNeg {
            protocol: Protocol::default(),
            capabilities,
            ..Default::default()
        };

        debug!(
            capabilities = ?out.capabilities,
            protocol = ?out.protocol,
            "option negotiation response sent",
        );

        Ok(out)
    }

    async fn connect(&mut self, connect: Connect) -> Result<Action, Self::Error> {
        info!(
            address = %connect.address(),
            port = connect.port,
            family = ?connect.family,
            host = %connect.hostname(),
            "connection accepted",
        );

        Ok(Continue.into())
    }

    async fn helo(&mut self, helo: Helo) -> Result<Action, Self::Error> {
        info!(helo = %helo.helo(), "HELO/EHLO received");
        Ok(Continue.into())
    }

    async fn mail(&mut self, mail: Mail) -> Result<Action, Self::Error> {
        info!(
            sender = %mail.sender(), args = ?mail.esmtp_args(),
            "MAIL FROM",
        );
        Ok(Continue.into())
    }

    async fn rcpt(&mut self, recipient: Recipient) -> Result<Action, Self::Error> {
        if let Some((_, domain)) = recipient.recipient().rsplit_once('@') {
            self.domain = Some(domain.trim_end_matches('>').to_owned());
        }

        info!(
            recipient = %recipient.recipient(),
            args = ?recipient.esmtp_args(),
            "RCPT TO",
        );
        Ok(Continue.into())
    }

    async fn data(&mut self) -> Result<Action, Self::Error> {
        debug!("DATA command received");
        Ok(Continue.into())
    }

    async fn header(&mut self, header: Header) -> Result<Action, Self::Error> {
        debug!(name = %header.name(), value = %header.value(), "header received");
        self.message.extend(header.name().as_bytes());
        self.message.extend(b": ");
        self.message.extend(header.value().as_bytes());
        self.message.extend(b"\r\n");
        Ok(Continue.into())
    }

    async fn end_of_header(&mut self) -> Result<Action, Self::Error> {
        debug!("end of headers");
        self.message.extend(b"\r\n");
        Ok(Continue.into())
    }

    async fn body(&mut self, body: Body) -> Result<Action, Self::Error> {
        debug!(len = body.as_bytes().len(), "body chunk received");
        self.message.extend(body.as_bytes());
        Ok(Continue.into())
    }

    async fn end_of_body(&mut self) -> Result<ModificationResponse, Self::Error> {
        info!("end of message");
        let Some(domain) = self.domain.take() else {
            warn!("no domain found from RCPT TO");
            return Ok(ModificationResponse::empty_continue());
        };

        let Some(selectors) = self.sealers.get(&domain) else {
            warn!("no ARC keys found for domain {domain}");
            return Ok(ModificationResponse::empty_continue());
        };

        // For simplicity, just use the first selector found
        let Some((_, sealer)) = selectors.iter().next() else {
            warn!(domain, "no ARC keys found for domain");
            return Ok(ModificationResponse::empty_continue());
        };

        // Parse the message
        let message = AuthenticatedMessage::parse(&self.message)
            .ok_or_else(|| anyhow::Error::msg("failed to parse message"))?;

        let auth_results = AuthenticationResults::new(&domain);
        let arc_output = ArcOutput::default();
        let arc_set = sealer.seal(&message, &auth_results, &arc_output)?;
        let headers = arc_set.to_header();
        let mut builder = ModificationResponse::builder();
        let mut current: Option<(String, String)> = None;

        for line in headers.lines() {
            if line.starts_with(|c: char| c.is_ascii_whitespace()) {
                // Continuation of previous header (folded header)
                if let Some((_, value)) = &mut current {
                    value.push_str(line);
                }
                continue;
            }

            if let Some((name, value)) = current.take() {
                builder.push(AddHeader::new(name.as_bytes(), value.trim().as_bytes()));
            }

            let Some((name, value)) = line.split_once(':') else {
                continue;
            };

            // Start collecting new header
            current = Some((name.trim().to_owned(), value.to_owned()));
        }

        // Don't forget the last header
        if let Some((name, value)) = current {
            builder.push(AddHeader::new(name.as_bytes(), value.trim().as_bytes()));
        }

        info!("ARC headers added");
        Ok(builder.contin())
    }

    async fn abort(&mut self) -> Result<(), Self::Error> {
        warn!("message aborted");
        self.reset();
        Ok(())
    }

    async fn quit(&mut self) -> Result<(), Self::Error> {
        info!("connection quit");
        self.reset();
        Ok(())
    }
}
