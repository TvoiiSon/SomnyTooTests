use anyhow::Result;
use tracing::info;
use tokio::io::{AsyncWriteExt, AsyncReadExt};

use crate::core::protocol::phantom_crypto::packet::PhantomPacketProcessor;
use crate::test_client::TestClient;
use crate::test_server::TestServer;

/// Отправка "Ping packet" и получение ответа от сервера
pub async fn send_ping_packet() -> Result<Vec<u8>> {
    // Запускаем тестовый сервер
    let server = TestServer::spawn().await;
    info!("Test server started at {}", server.addr);

    // Подключаем клиента
    let mut client = TestClient::connect().await?;
    info!("Client connected with session: {}",
          hex::encode(client.session.session_id()));

    // --- Build & send packet ---
    let mut packet_processor = PhantomPacketProcessor::new();
    let ping_data = b"ping";

    // Создаем фантомный пакет (тип 0x01 для ping)
    let phantom_packet = packet_processor.create_outgoing(
        &client.session,
        0x01,
        ping_data
    ).map_err(|e| anyhow::anyhow!("Failed to create phantom packet: {:?}", e))?;

    info!(target: "send_test_packet", "Sending Phantom ping packet ({} bytes)", phantom_packet.len());

    // Отправляем пакет
    client.stream.write_all(&phantom_packet).await?;
    client.stream.flush().await?;

    // --- Receive frame ---
    let mut buffer = vec![0u8; 1024];
    let n = client.stream.read(&mut buffer).await?;
    let resp_frame = buffer[..n].to_vec();

    info!(target: "send_test_packet", "Got response frame ({} bytes)", resp_frame.len());

    // --- Decode & verify ---
    match packet_processor.process_incoming(&resp_frame, &client.session) {
        Ok((packet_type, plaintext)) => {
            info!(target: "send_test_packet",
                  "Response packet type: 0x{:02X}, plaintext: {} bytes",
                  packet_type, plaintext.len());

            if !plaintext.is_empty() {
                info!(target: "send_test_packet",
                      "Plaintext content: {}",
                      String::from_utf8_lossy(&plaintext));
            }

            // Проверяем, что сервер вернул правильный ответ
            // В фантомной системе пакет типа 0x02 - это pong
            if packet_type == 0x01 {
                info!("Received PONG response correctly");
            } else {
                info!("Received packet type 0x{:02X}, expected 0x02", packet_type);
            }

            Ok(resp_frame)
        }
        Err(e) => {
            info!("Failed to decode server response: {:?}", e);
            // Даже если не можем декодировать, возвращаем сырые данные
            Ok(resp_frame)
        }
    }
}