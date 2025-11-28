use miltr_common::{
    actions::{Action, Continue},
    commands::{Body, Connect, Header, Helo, Mail, Recipient},
    modifications::ModificationResponse,
    optneg::{Capability, OptNeg, Protocol},
};
use miltr_server::{Milter, Server};
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{error, info, level_filters::LevelFilter, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with(tracing_subscriber::fmt::layer().with_file(true))
        .init();

    let listener = TcpListener::bind("127.0.0.1:8765").await?;
    info!("listening on 127.0.0.1:8765");
    let mut milter = ArcMilter::default();
    let mut server = Server::default_postfix(&mut milter);

    loop {
        let (stream, addr) = listener.accept().await?;
        info!("accepted connection from {addr}");
        if let Err(error) = server.handle_connection(stream.compat()).await {
            error!(%addr, %error, "milter error");
        }
    }
}

#[derive(Default)]
struct ArcMilter {
    headers: Vec<Header>,
    body: Vec<u8>,
}

impl ArcMilter {
    fn reset(&mut self) {
        self.headers.clear();
        self.body.clear();
    }
}

#[async_trait::async_trait]
impl Milter for ArcMilter {
    type Error = std::io::Error;

    async fn option_negotiation(
        &mut self,
        theirs: OptNeg,
    ) -> Result<OptNeg, miltr_server::Error<Self::Error>> {
        info!(
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

        info!(
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
        info!(
            recipient = %recipient.recipient(),
            args = ?recipient.esmtp_args(),
            "RCPT TO",
        );
        Ok(Continue.into())
    }

    async fn data(&mut self) -> Result<Action, Self::Error> {
        info!("DATA command received");
        Ok(Continue.into())
    }

    async fn header(&mut self, header: Header) -> Result<Action, Self::Error> {
        info!(name = %header.name(), value = %header.value(), "header received");
        self.headers.push(header);
        Ok(Continue.into())
    }

    async fn end_of_header(&mut self) -> Result<Action, Self::Error> {
        info!(received = self.headers.len(), "end of headers");
        Ok(Continue.into())
    }

    async fn body(&mut self, body: Body) -> Result<Action, Self::Error> {
        info!(len = body.as_bytes().len(), "body chunk received");
        self.body.extend_from_slice(body.as_bytes());
        Ok(Continue.into())
    }

    async fn end_of_body(&mut self) -> Result<ModificationResponse, Self::Error> {
        info!("end of message");
        Ok(ModificationResponse::empty_continue())
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
