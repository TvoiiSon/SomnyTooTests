use anyhow::Result;
use tracing::info;

use crate::core::protocol::packets::encoder::packet_builder::PacketBuilder;
use crate::core::protocol::packets::encoder::frame_writer::write_frame;
use crate::core::protocol::packets::decoder::frame_reader::read_frame;
use crate::core::protocol::packets::decoder::packet_parser::{PacketParser, PacketType};
use crate::test_client::TestClient;
use crate::test_server::TestServer;

/// Отправка "Ping packet" и получение ответа от сервера
pub async fn send_ping_packet() -> Result<Vec<u8>> {
    let _ = TestServer::spawn().await;
    let mut client = TestClient::connect().await?;

    // --- Build & send packet ---
    let pkt = PacketBuilder::build_encrypted_packet(&client.ctx, 0x01, b"").await;
    info!(target: "send_test_packet", "Sending Test packet ({} bytes)", pkt.len());
    let _ = write_frame(&mut client.stream, &pkt).await;

    // --- Receive frame ---
    let resp_frame = read_frame(&mut client.stream).await?;
    info!(target: "send_test_packet", "Got response frame ({} bytes)", resp_frame.len());

    // --- Decode & verify ---
    match PacketParser::decode_packet(&client.ctx, &resp_frame) {
        Ok((ptype_raw, plaintext)) => {
            let ptype = PacketType::from(ptype_raw);
            info!(target: "send_test_packet", "Response packet type: {:?}, plaintext: {}", ptype, String::from_utf8_lossy(&plaintext));

            // Проверяем, что сервер вернул правильный ответ
            assert_eq!(ptype, PacketType::Ping);

            Ok(resp_frame)
        }
        Err(e) => panic!("Failed to decode server response: {}", e),
    }
}
