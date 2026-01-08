use tracing::info;
use anyhow::Result;
use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::time::Duration;
use std::sync::Arc;

use crate::core::protocol::phantom_crypto::{
    core::{
        keys::PhantomSession,
        handshake::{perform_phantom_handshake, HandshakeRole},
    },
};
use crate::config::CONFIG;

pub struct TestClient {
    pub stream: TcpStream,
    pub session: Arc<PhantomSession>,
}

impl TestClient {
    pub async fn connect() -> Result<Self> {
        let mut stream = TcpStream::connect(CONFIG.server_addr()).await?;
        info!(target: "test", "Client connected to {}", CONFIG.server_addr());

        // Используем фантомный handshake
        let handshake_result = perform_phantom_handshake(&mut stream, HandshakeRole::Client).await
            .map_err(|e| anyhow::anyhow!("Phantom handshake failed: {:?}", e))?;

        info!(target: "test", "Phantom handshake completed, session_id: {}",
              hex::encode(handshake_result.session.session_id()));

        Ok(Self {
            stream,
            session: Arc::new(handshake_result.session),
        })
    }

    pub async fn send_ping(&mut self) -> Result<()> {
        // Создаем простой ping пакет (тип 0x20 для данных)
        let ping_data = b"ping";

        // В тестовом режиме просто отправляем сырые данные
        // В реальной реализации здесь будет шифрование через фантомную систему
        let mut packet = vec![0x01]; // Тип пакета: данные
        packet.extend_from_slice(ping_data);

        self.stream.write_all(&packet).await?;
        info!(target: "test", "Sent ping packet, size: {} bytes", packet.len());

        Ok(())
    }

    pub async fn receive_response(&mut self) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; 1024];
        match self.stream.read(&mut buffer).await {
            Ok(0) => {
                info!("Connection closed by server");
                Ok(Vec::new())
            }
            Ok(n) => {
                buffer.truncate(n);
                info!("Received {} bytes from server", n);
                Ok(buffer)
            }
            Err(e) => Err(anyhow::anyhow!("Failed to read from server: {}", e)),
        }
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        self.stream.shutdown().await?;
        tokio::time::sleep(Duration::from_millis(10)).await;
        Ok(())
    }
}

// Простая функция для тестирования без полной фантомной системы
pub async fn test_phantom_connection() -> Result<()> {
    info!("Testing phantom connection...");

    let mut client = TestClient::connect().await?;
    info!("Connected successfully");

    // Отправляем тестовый пинг
    client.send_ping().await?;

    // Ждем ответ (таймаут 5 секунд)
    match tokio::time::timeout(Duration::from_secs(5), client.receive_response()).await {
        Ok(Ok(response)) => {
            info!("Received response: {} bytes", response.len());
        }
        Ok(Err(e)) => {
            info!("Error receiving response: {}", e);
        }
        Err(_) => {
            info!("Timeout waiting for response");
        }
    }

    client.shutdown().await?;
    info!("Test completed");

    Ok(())
}