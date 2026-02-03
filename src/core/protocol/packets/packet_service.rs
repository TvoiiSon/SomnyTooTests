use std::sync::Arc;
use std::net::SocketAddr;
use tracing::{info, error, debug};
use std::time::{Instant, Duration};

use crate::core::protocol::phantom_crypto::core::keys::PhantomSession;

pub struct PacketProcessingResult {
    pub response: Vec<u8>,
    pub should_encrypt: bool,
    pub packet_type: u8,
}

pub struct PhantomPacketService;

impl PhantomPacketService {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn process_packet(
        &self,
        session: Arc<PhantomSession>,
        packet_type: u8,
        payload: Vec<u8>,
        client_ip: SocketAddr,
    ) -> Result<PacketProcessingResult, Box<dyn std::error::Error + Send + Sync>> {
        let process_start = Instant::now();

        debug!("Processing phantom packet type: 0x{:02X} from {}, session: {}",
              packet_type, client_ip, hex::encode(session.session_id()));

        let response_data = match packet_type {
            0x01 => {
                self.handle_ping(payload, session.clone(), client_ip).await?
            }
            0x10 => {
                self.handle_heartbeat(session.session_id(), client_ip).await?
            }
            _ => {
                self.handle_unknown_packet(packet_type, payload, session.clone(), client_ip).await?
            }
        };

        let total_time = process_start.elapsed();
        if total_time > Duration::from_millis(5) {
            debug!("PhantomPacketService total processing time: {:?} for 0x{:02X}",
                  total_time, packet_type);
        }

        Ok(PacketProcessingResult {
            response: response_data,
            should_encrypt: true,
            packet_type,
        })
    }

    async fn handle_ping(
        &self,
        payload: Vec<u8>,
        _session: Arc<PhantomSession>,
        client_ip: SocketAddr,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let start = Instant::now();

        info!("👻 Ping packet received from {}: {} ({} bytes)",
        client_ip, String::from_utf8_lossy(&payload), payload.len());

        // Клиент получает PING - отправляем PONG обратно
        let result = b"PONG".to_vec();

        let elapsed = start.elapsed();

        if elapsed > Duration::from_millis(1) {
            debug!("Ping handle took {:?}", elapsed);
        }

        Ok(result)
    }

    async fn handle_heartbeat(
        &self,
        session_id: &[u8],
        client_ip: SocketAddr,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let start = Instant::now();

        debug!("Processing phantom heartbeat from {} session: {}",
              client_ip, hex::encode(session_id));

        let heartbeat_result = b"Heartbeat acknowledged".to_vec();

        let total_time = start.elapsed();
        debug!("Phantom heartbeat processing: {:?}", total_time);

        Ok(heartbeat_result)
    }

    async fn handle_unknown_packet(
        &self,
        packet_type: u8,
        _payload: Vec<u8>,
        session: Arc<PhantomSession>,
        client_ip: SocketAddr,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        error!("Unknown phantom packet type: 0x{:02X} from {}, session: {}",
               packet_type, client_ip, hex::encode(session.session_id()));

        Ok(format!("Unknown phantom packet type: 0x{:02X}", packet_type).into_bytes())
    }
}

impl Clone for PhantomPacketService {
    fn clone(&self) -> Self {
        Self {}
    }
}