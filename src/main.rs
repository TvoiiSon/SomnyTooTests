use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use anyhow::Result;
use tracing_subscriber::{FmtSubscriber, EnvFilter};
use tracing::{info, error, warn, debug};

use somnytoo_test::config::CLIENT_CONFIG;
use somnytoo_test::core::protocol::phantom_crypto::core::handshake::{perform_phantom_handshake, HandshakeRole};
use somnytoo_test::core::protocol::phantom_crypto::packet::PhantomPacketProcessor;

#[tokio::main]
async fn main() -> Result<()> {
    // Настройка логирования
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            let mut filter = EnvFilter::new("info");
            filter = filter.add_directive("tokio=warn".parse().unwrap());
            filter = filter.add_directive("runtime=warn".parse().unwrap());
            filter = filter.add_directive("tracing=warn".parse().unwrap());
            filter
        });

    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter)
        .with_target(true)
        .with_level(true)
        .without_time()
        .compact()
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    info!("🚀 Starting Phantom Protocol Client...");
    info!("📝 Server: {}", CLIENT_CONFIG.server_addr());

    run_client().await
}

async fn run_client() -> Result<()> {
    let addr = CLIENT_CONFIG.server_addr();

    info!("🔗 Connecting to server...");

    // Подключение к серверу
    let stream = tokio::time::timeout(
        Duration::from_millis(CLIENT_CONFIG.connect_timeout_ms),
        TcpStream::connect(&addr)
    ).await??;

    info!("✅ Connected to server");

    // Настраиваем сокет
    stream.set_nodelay(true)?;
    let (read_stream, write_stream) = stream.into_split();

    // Выполняем handshake
    info!("🤝 Performing phantom handshake...");

    // Для handshake нам нужен целый поток, временно воссоединяем
    let mut temp_stream = read_stream.reunite(write_stream)?;
    let handshake_result = perform_phantom_handshake(
        &mut temp_stream,
        HandshakeRole::Client
    ).await?;

    // Снова разделяем
    let (mut read_stream, mut write_stream) = temp_stream.into_split();

    let session = Arc::new(handshake_result.session);

    info!("✅ Handshake completed!");
    info!("🕐 Handshake time: {:?}", handshake_result.handshake_time);
    info!("🎯 Session ID: {}", hex::encode(session.session_id()));

    // Создаем PING пакет
    info!("🎯 Creating PING packet...");
    let packet_processor = PhantomPacketProcessor::new();

    let ping_packet = packet_processor.create_outgoing_vec(
        &session,
        0x01, // PING packet type
        b"PING from client"
    )?;

    info!("📦 Created PING packet: {} bytes", ping_packet.len());

    // Отправляем PING
    info!("📤 Sending PING packet...");
    send_frame(&mut write_stream, &ping_packet).await?;
    info!("✅ PING sent successfully");

    // Читаем ответ от сервера
    info!("👂 Waiting for server response...");

    match tokio::time::timeout(Duration::from_secs(10), read_frame(&mut read_stream)).await {
        Ok(Ok(frame_data)) => {
            if frame_data.is_empty() {
                info!("📭 Server closed connection gracefully");
                return Ok(());
            }

            info!("📥 Received {} bytes from server", frame_data.len());

            // Пробуем расшифровать ответ
            match packet_processor.process_incoming_vec(&frame_data, &session) {
                Ok((packet_type, payload)) => {
                    let payload_str = String::from_utf8_lossy(&payload);

                    if packet_type == 0x01 && payload_str == "PONG" {
                        info!("✅ PONG received successfully!");

                        info!("🎉 Mission accomplished!");
                    } else {
                        warn!("⚠️ Unexpected response: type=0x{:02x}, payload={}",
                              packet_type, payload_str);
                    }
                }
                Err(e) => {
                    warn!("❌ Failed to decrypt response: {}", e);
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

    // Завершаем соединение
    graceful_shutdown(&mut write_stream).await;

    info!("👋 Client shutdown complete");
    Ok(())
}

// Простая функция отправки фрейма
async fn send_frame(write_stream: &mut (impl AsyncWriteExt + Unpin), data: &[u8]) -> Result<()> {
    let header = (data.len() as u32).to_be_bytes();

    write_stream.write_all(&header).await?;
    write_stream.write_all(data).await?;
    write_stream.flush().await?;

    Ok(())
}

// Простая функция чтения фрейма
async fn read_frame(read_stream: &mut (impl AsyncReadExt + Unpin)) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    read_stream.read_exact(&mut header).await?;

    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Ok(Vec::new());
    }

    let mut data = vec![0u8; length];
    read_stream.read_exact(&mut data).await?;

    Ok(data)
}

// Грациозное завершение соединения
async fn graceful_shutdown(write_stream: &mut (impl AsyncWriteExt + Unpin)) {
    if let Err(e) = write_stream.shutdown().await {
        debug!("Stream shutdown error: {}", e);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
}