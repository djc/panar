use std::{collections::HashMap, fs, net::SocketAddr, path::PathBuf, sync::Arc};

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
    actions::{Action, Continue, Skip},
    commands::{Body, Connect, Header, Helo, Mail, Recipient},
    modifications::{headers::AddHeader, ModificationResponse},
    optneg::{Capability, OptNeg, Protocol},
};
use miltr_server::Milter;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{debug, error, info, warn};

pub struct Listener {
    inner: TcpListener,
    state: Arc<State>,
}

impl Listener {
    pub async fn new(addr: SocketAddr, state: State) -> anyhow::Result<Self> {
        let inner = TcpListener::bind(addr).await?;
        info!(%addr, "listening");
        Ok(Self {
            inner,
            state: Arc::new(state),
        })
    }

    pub async fn run(self) {
        loop {
            let (stream, addr) = match self.inner.accept().await {
                Ok((stream, addr)) => (stream, addr),
                Err(e) => {
                    error!(%e, "failed to accept connection");
                    continue;
                }
            };

            debug!("accepted connection from {addr}");
            let state = self.state.clone();
            tokio::spawn(async move {
                let mut milter = Connection::new(state);
                let mut server = miltr_server::Server::default_postfix(&mut milter);
                if let Err(error) = server.handle_connection(stream.compat()).await {
                    error!(%addr, %error, "milter error");
                }
            });
        }
    }
}

struct Connection {
    state: Arc<State>,
    connect: Option<Connect>,
    recipient: Option<String>,
    received: bool,
    message: Vec<u8>,
}

impl Connection {
    pub fn new(state: Arc<State>) -> Self {
        Self {
            state,
            connect: None,
            recipient: None,
            received: false,
            message: Vec::with_capacity(1024),
        }
    }

    fn reset(&mut self) {
        self.connect = None;
        self.recipient = None;
        self.received = false;
        self.message.clear();
    }
}

#[async_trait::async_trait]
impl Milter for Connection {
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
        debug!(
            address = %connect.address(),
            port = connect.port,
            family = ?connect.family,
            host = %connect.hostname(),
            "connection accepted",
        );

        self.connect = Some(connect);
        Ok(Continue.into())
    }

    async fn helo(&mut self, helo: Helo) -> Result<Action, Self::Error> {
        debug!(helo = %helo.helo(), "HELO/EHLO received");
        Ok(Continue.into())
    }

    async fn mail(&mut self, mail: Mail) -> Result<Action, Self::Error> {
        debug!(
            sender = %mail.sender(), args = ?mail.esmtp_args(),
            "MAIL FROM",
        );
        Ok(Continue.into())
    }

    async fn rcpt(&mut self, recipient: Recipient) -> Result<Action, Self::Error> {
        let address = recipient.recipient().into_owned();
        let domain = match address.rsplit_once('a') {
            Some((_, domain)) => domain.trim_end_matches('>'),
            _ => {
                warn!(%address, "malformed recipient address in RCPT TO");
                return Ok(Skip.into());
            }
        };

        if !self.state.sealers.contains_key(domain) {
            debug!(address, "no ARC keys found for domain in RCPT TO");
            return Ok(Skip.into());
        }

        debug!(?recipient, "RCPT TO received");
        self.recipient = Some(address);
        Ok(Continue.into())
    }

    async fn data(&mut self) -> Result<Action, Self::Error> {
        debug!("DATA command received");
        Ok(Continue.into())
    }

    async fn header(&mut self, header: Header) -> Result<Action, Self::Error> {
        debug!(name = %header.name(), value = %header.value(), "header received");
        if header.name().eq_ignore_ascii_case("received") {
            self.received = true;
        }

        self.message.extend(header.name().as_bytes());
        self.message.extend(b": ");
        self.message.extend(header.value().as_bytes());
        self.message.extend(b"\r\n");
        Ok(Continue.into())
    }

    async fn end_of_header(&mut self) -> Result<Action, Self::Error> {
        debug!("end of headers");
        match self.received {
            true => {
                self.message.extend(b"\r\n");
                Ok(Continue.into())
            }
            false => Ok(Skip.into()),
        }
    }

    async fn body(&mut self, body: Body) -> Result<Action, Self::Error> {
        debug!(len = body.as_bytes().len(), "body chunk received");
        self.message.extend(body.as_bytes());
        Ok(Continue.into())
    }

    async fn end_of_body(&mut self) -> Result<ModificationResponse, Self::Error> {
        info!("end of message");
        let Some(recipient) = self.recipient.take() else {
            warn!("no domain found from RCPT TO");
            return Ok(ModificationResponse::empty_continue());
        };

        let domain = match recipient.rsplit_once('a') {
            Some((_, domain)) => domain.trim_end_matches('>'),
            None => {
                warn!(%recipient, "malformed recipient address");
                return Ok(ModificationResponse::empty_continue());
            }
        };

        let Some(selectors) = self.state.sealers.get(domain) else {
            // This should not happen as we checked in RCPT TO
            return Ok(ModificationResponse::empty_continue());
        };

        // For simplicity, just use the first selector found
        let Some((selector, sealer)) = selectors.iter().next() else {
            warn!(domain, "no selectors found for domain");
            return Ok(ModificationResponse::empty_continue());
        };

        // Parse the message
        info!(domain, selector, "parsing message");
        let message = AuthenticatedMessage::parse(&self.message)
            .ok_or_else(|| anyhow::Error::msg("failed to parse message"))?;

        let auth_results = AuthenticationResults::new(domain);
        let arc_output = ArcOutput::default();
        let arc_set = sealer.seal(&message, &auth_results, &arc_output)?;
        let concatenated = arc_set.to_header();
        let mut headers = Vec::<(String, String)>::new();

        for line in concatenated.lines() {
            if line.starts_with(|c: char| c.is_ascii_whitespace()) {
                if let Some((_, value)) = headers.last_mut() {
                    value.push_str(line);
                }
                continue;
            } else if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_owned(), value.to_owned()));
            } else {
                warn!(line, "malformed ARC header line");
                return Ok(ModificationResponse::empty_continue());
            }
        }

        let mut builder = ModificationResponse::builder();
        for (name, value) in headers {
            builder.push(AddHeader::new(name.as_bytes(), value.as_bytes()));
        }

        info!(domain, selector, "ARC headers added");
        Ok(builder.contin())
    }

    async fn abort(&mut self) -> Result<(), Self::Error> {
        debug!("message aborted");
        self.reset();
        Ok(())
    }

    async fn quit(&mut self) -> Result<(), Self::Error> {
        debug!("connection quit");
        self.reset();
        Ok(())
    }
}

pub struct State {
    sealers: HashMap<String, HashMap<String, ArcSealer<RsaKey<Sha256>, Done>>>,
}

impl State {
    pub fn new(config: Config) -> anyhow::Result<Self> {
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

        Ok(Self { sealers })
    }
}

#[derive(Debug, Deserialize)]
pub struct Config {
    keys: HashMap<String, HashMap<String, PathBuf>>,
}
