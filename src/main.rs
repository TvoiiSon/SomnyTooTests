use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt};
use anyhow::Result;
use tracing_subscriber::{FmtSubscriber, EnvFilter};
use tracing::{info, error, warn};

use somnytoo_test::config::CLIENT_CONFIG;
use somnytoo_test::core::protocol::phantom_crypto::core::handshake::{perform_phantom_handshake, HandshakeRole};
use somnytoo_test::core::protocol::phantom_crypto::packet::PhantomPacketProcessor;
use somnytoo_test::core::protocol::packets::frame_reader::read_frame;

#[tokio::main]
async fn main() -> Result<()> {
    // Настройка логирования
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter)
        .with_target(true)
        .with_level(true)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    info!("🚀 Starting Phantom Protocol Client (SYNCED)...");
    info!("📝 Server: {}", CLIENT_CONFIG.server_addr());

    run_client().await
}

async fn run_client() -> Result<()> {
    let addr = CLIENT_CONFIG.server_addr();

    info!("🔗 Connecting to server at {}...", addr);

    // Подключение к серверу
    let mut stream = tokio::time::timeout(
        Duration::from_millis(CLIENT_CONFIG.connect_timeout_ms),
        TcpStream::connect(&addr)
    ).await??;

    info!("✅ Connected to server");

    // Выполняем handshake
    info!("🤝 Performing phantom handshake...");
    let handshake_result = perform_phantom_handshake(
        &mut stream,
        HandshakeRole::Client
    ).await?;

    let session = Arc::new(handshake_result.session);
    let session_id = session.session_id();

    info!("✅ Handshake completed! Session ID: {}", hex::encode(session_id));
    info!("🕐 Handshake time: {:?}", handshake_result.handshake_time);

    // Создаем PING пакет
    info!("🎯 Creating PING packet...");
    let packet_processor = PhantomPacketProcessor::new();

    let ping_packet = match packet_processor.create_outgoing_vec(
        &session,
        0x01, // PING packet type
        b"PING from client"
    ) {
        Ok(packet) => packet,
        Err(e) => {
            error!("❌ Failed to create PING packet: {}", e);
            return Err(e.into());
        }
    };

    info!("📦 Created PING packet: {} bytes", ping_packet.len());

    // Отправляем как фрейм [4 байта длины][данные]
    let len_bytes = (ping_packet.len() as u32).to_be_bytes();

    // Записываем длину
    if let Err(e) = stream.write_all(&len_bytes).await {
        error!("❌ Failed to write length: {}", e);
        return Err(e.into());
    }

    // Записываем данные
    if let Err(e) = stream.write_all(&ping_packet).await {
        error!("❌ Failed to write packet data: {}", e);
        return Err(e.into());
    }

    // Flush
    if let Err(e) = stream.flush().await {
        error!("❌ Failed to flush: {}", e);
        return Err(e.into());
    }

    info!("✅ PING packet sent successfully ({} bytes total)", ping_packet.len() + 4);
    info!("📤 Payload: 'PING from client'");

    // Читаем ответ от сервера
    info!("👂 Waiting for server response (10s timeout)...");

    match tokio::time::timeout(Duration::from_secs(30), read_frame(&mut stream)).await {
        Ok(Ok(frame_data)) => {
            if frame_data.is_empty() {
                info!("📭 Server closed connection");
                return Ok(());
            }

            info!("📥 Received frame from server: {} bytes", frame_data.len());

            // Пробуем расшифровать ответ
            match packet_processor.process_incoming_vec(&frame_data, &session) {
                Ok((packet_type, payload)) => {
                    info!("✅ DECRYPTED SERVER RESPONSE:");
                    info!("  Packet type: 0x{:02x}", packet_type);
                    info!("  Payload: {}", String::from_utf8_lossy(&payload));

                    if packet_type == 0x01 && payload.starts_with(b"PONG") {
                        info!("🎉 SUCCESS: PONG received from server!");
                        info!("💫 Mission accomplished!");
                    } else {
                        warn!("⚠️ Unexpected response from server");
                    }
                }
                Err(e) => {
                    warn!("❌ Failed to decrypt server response: {}", e);
                    info!("Raw data (hex): {}", hex::encode(&frame_data));
                }
            }
        }
        Ok(Err(e)) => {
            error!("❌ Failed to read frame: {}", e);
        }
        Err(_) => {
            error!("⏰ Timeout waiting for server response");
        }
    }

    info!("👋 Client shutdown complete");

    // Короткая пауза перед завершением
    tokio::time::sleep(Duration::from_millis(500)).await;

    Ok(())
}