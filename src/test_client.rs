use tracing::info;
use anyhow::Result;
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use tokio::time::Duration;

use crate::core::protocol::crypto::handshake::handshake::{perform_handshake, HandshakeRole};
use crate::core::protocol::crypto::key_manager::session_keys::SessionKeys;
use crate::config::CONFIG;

pub struct TestClient {
    pub stream: TcpStream,
    pub ctx: SessionKeys,
}

impl TestClient {
    pub async fn connect() -> Result<Self> {
        let mut stream = TcpStream::connect(CONFIG.server_addr()).await?;
        info!(target: "test", "Client connected to {}", CONFIG.server_addr());

        // Используем УНИФИЦИРОВАННЫЙ handshake!
        let handshake_result = perform_handshake(&mut stream, HandshakeRole::Client).await?;

        info!(target: "test", "Handshake completed, session_id: {}",
              hex::encode(handshake_result.session_keys.session_id));

        Ok(Self {
            stream,
            ctx: handshake_result.session_keys
        })
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        self.stream.shutdown().await?;
        tokio::time::sleep(Duration::from_millis(10)).await;
        Ok(())
    }
}
