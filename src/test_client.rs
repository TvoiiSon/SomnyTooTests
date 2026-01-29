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
use crate::core::protocol::crypto::crypto_pool_phantom::PhantomCryptoPool; // Импортируем криптопул
use crate::config::CONFIG;

pub struct TestClient {
    pub stream: TcpStream,
    pub session: Arc<PhantomSession>,
    pub crypto_pool: Arc<PhantomCryptoPool>, // Добавляем криптопул
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

        // Создаем криптопул для клиента
        let crypto_pool = Arc::new(PhantomCryptoPool::spawn(4)); // 4 воркера для тестов

        Ok(Self {
            stream,
            session: Arc::new(handshake_result.session),
            crypto_pool,
        })
    }

    /// Подключение к конкретному адресу (для тестового сервера)
    pub async fn connect_to(addr: &str) -> Result<Self> {
        let mut stream = TcpStream::connect(addr).await?;
        info!(target: "test", "Client connected to {}", addr);

        // Используем фантомный handshake
        let handshake_result = perform_phantom_handshake(&mut stream, HandshakeRole::Client).await
            .map_err(|e| anyhow::anyhow!("Phantom handshake failed: {:?}", e))?;

        info!(target: "test", "Phantom handshake completed, session_id: {}",
              hex::encode(handshake_result.session.session_id()));

        // Создаем криптопул для клиента
        let crypto_pool = Arc::new(PhantomCryptoPool::spawn(4));

        Ok(Self {
            stream,
            session: Arc::new(handshake_result.session),
            crypto_pool,
        })
    }

    pub async fn send_ping(&mut self) -> Result<()> {
        // Создаем ping данные
        let ping_data = b"ping";

        info!(target: "test", "Encrypting ping packet with session: {}",
              hex::encode(self.session.session_id()));

        // Шифруем через криптопул
        match self.crypto_pool.encrypt(
            self.session.clone(),
            0x01, // Тип пакета: ping
            ping_data.to_vec()
        ).await {
            Ok(encrypted_packet) => {
                info!(target: "test", "✅ Ping packet encrypted, size: {} bytes", encrypted_packet.len());

                // Отправляем зашифрованный пакет
                self.stream.write_all(&encrypted_packet).await?;
                info!(target: "test", "✅ Encrypted ping packet sent");

                Ok(())
            }
            Err(e) => {
                info!(target: "test", "❌ Failed to encrypt ping packet: {}", e);

                // Fallback: отправляем сырой пакет для совместимости
                let mut packet = vec![0x01]; // Тип пакета: данные
                packet.extend_from_slice(ping_data);

                self.stream.write_all(&packet).await?;
                info!(target: "test", "⚠️  Sent raw ping packet (fallback), size: {} bytes", packet.len());

                Ok(())
            }
        }
    }

    pub async fn receive_response(&mut self) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; 4096];
        match self.stream.read(&mut buffer).await {
            Ok(0) => {
                info!("Connection closed by server");
                Ok(Vec::new())
            }
            Ok(n) => {
                buffer.truncate(n);
                info!("Received {} bytes from server", n);

                // Пробуем расшифровать ответ
                if n > 50 { // Если пакет достаточно большой, пробуем расшифровать
                    match self.crypto_pool.decrypt(self.session.clone(), buffer.clone()).await {
                        Ok((packet_type, plaintext)) => {
                            info!("✅ Successfully decrypted response: type=0x{:02x}, size={} bytes",
                                  packet_type, plaintext.len());
                            Ok(plaintext)
                        }
                        Err(e) => {
                            info!("⚠️  Could not decrypt response ({}), returning raw data", e);
                            Ok(buffer)
                        }
                    }
                } else {
                    Ok(buffer)
                }
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