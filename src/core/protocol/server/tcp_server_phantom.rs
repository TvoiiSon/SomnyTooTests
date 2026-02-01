use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{info, error};

use crate::core::protocol::phantom_crypto::core::handshake::{perform_phantom_handshake, HandshakeRole};
use crate::core::protocol::phantom_crypto::packet::PhantomPacketProcessor;

pub async fn connect_to_phantom_server(
    server_addr: &str,
) -> Result<(TcpStream, Arc<PhantomPacketProcessor>), Box<dyn std::error::Error + Send + Sync>> {
    info!("🔗 Connecting to phantom server at {}...", server_addr);

    // Подключение к серверу
    let mut stream = match timeout(
        Duration::from_secs(10),
        TcpStream::connect(server_addr)
    ).await {
        Ok(Ok(stream)) => {
            info!("✅ Connected to server at {}", server_addr);
            stream
        }
        Ok(Err(e)) => {
            error!("❌ Connection failed: {}", e);
            return Err(Box::new(e));
        }
        Err(_) => {
            error!("❌ Connection timeout");
            return Err("Connection timeout".into());
        }
    };

    // Выполнение handshake
    info!("🤝 Performing phantom handshake...");
    let handshake_result = perform_phantom_handshake(&mut stream, HandshakeRole::Client).await?;

    info!("✅ Handshake completed! Session ID: {}",
          hex::encode(handshake_result.session.session_id()));
    info!("🕐 Handshake time: {:?}", handshake_result.handshake_time);

    let packet_processor = Arc::new(PhantomPacketProcessor::new());

    Ok((stream, packet_processor))
}

pub async fn send_phantom_packet(
    stream: &mut TcpStream,
    packet_processor: &PhantomPacketProcessor,
    session: &crate::core::protocol::phantom_crypto::core::keys::PhantomSession,
    packet_type: u8,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Создаем зашифрованный пакет
    let packet_data = packet_processor.create_outgoing_vec(session, packet_type, payload)?;

    // Отправляем пакет
    crate::core::protocol::packets::frame_writer::write_frame(stream, &packet_data).await?;

    info!("📤 Packet 0x{:02X} sent ({} bytes)", packet_type, payload.len());
    Ok(())
}

pub async fn receive_phantom_packet(
    stream: &mut tokio::net::tcp::OwnedReadHalf,
    packet_processor: &PhantomPacketProcessor,
    session: &crate::core::protocol::phantom_crypto::core::keys::PhantomSession,
) -> Result<Option<(u8, Vec<u8>)>, Box<dyn std::error::Error + Send + Sync>> {
    // Читаем фрейм
    let frame_data = crate::core::protocol::packets::frame_reader::read_frame(stream).await?;

    if frame_data.is_empty() {
        return Ok(None); // Соединение закрыто
    }

    // Обрабатываем пакет
    let (packet_type, decrypted_data) = packet_processor.process_incoming_vec(&frame_data, session)?;

    Ok(Some((packet_type, decrypted_data)))
}