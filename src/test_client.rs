use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::{info};

use crate::core::protocol::phantom_crypto::core::handshake::{perform_phantom_handshake, HandshakeRole};
use crate::core::protocol::phantom_crypto::packet::PhantomPacketProcessor;

/// Упрощенный тестовый клиент без packet_service
pub struct TestClient {
    pub stream: TcpStream,
    pub session: Arc<crate::core::protocol::phantom_crypto::core::keys::PhantomSession>,
    pub packet_processor: PhantomPacketProcessor,
}

impl TestClient {
    pub async fn connect(server_addr: &str) -> anyhow::Result<Self> {
        info!("🔗 Test client connecting to {}...", server_addr);

        let mut stream = tokio::time::timeout(
            Duration::from_secs(10),
            TcpStream::connect(server_addr)
        ).await??;

        info!("✅ Connected to server");

        // Выполняем handshake
        let handshake_result = perform_phantom_handshake(&mut stream, HandshakeRole::Client).await?;
        let session = Arc::new(handshake_result.session);

        info!("✅ Handshake completed. Session ID: {}", hex::encode(session.session_id()));

        Ok(Self {
            stream,
            session,
            packet_processor: PhantomPacketProcessor::new(),
        })
    }

    pub async fn send_ping(&mut self) -> anyhow::Result<()> {
        let packet_data = self.packet_processor.create_outgoing_vec(
            &self.session,
            0x01, // PING packet type
            b"Test PING from client"
        )?;

        crate::core::protocol::packets::frame_writer::write_frame(
            &mut self.stream,
            &packet_data
        ).await?;

        info!("🏓 Test PING sent");
        Ok(())
    }

    pub async fn send_custom_packet(&mut self, packet_type: u8, data: &[u8]) -> anyhow::Result<()> {
        let packet_data = self.packet_processor.create_outgoing_vec(
            &self.session,
            packet_type,
            data
        )?;

        crate::core::protocol::packets::frame_writer::write_frame(
            &mut self.stream,
            &packet_data
        ).await?;

        info!("📤 Custom packet 0x{:02X} sent ({} bytes)", packet_type, data.len());
        Ok(())
    }

    pub async fn receive_packet(&mut self) -> anyhow::Result<Option<(u8, Vec<u8>)>> {
        let frame_data = crate::core::protocol::packets::frame_reader::read_frame(
            &mut self.stream
        ).await?;

        if frame_data.is_empty() {
            return Ok(None);
        }

        let (packet_type, decrypted_data) = self.packet_processor.process_incoming_vec(
            &frame_data,
            &self.session
        )?;

        Ok(Some((packet_type, decrypted_data)))
    }
}