use std::sync::Arc;
use std::time::Duration;
use tracing::{info, error};
use bytes::Bytes;

use crate::core::protocol::phantom_crypto::{
    packet::PhantomPacketProcessor,
    core::keys::PhantomSession,
    batch::io::writer::batch_writer::{BatchWriter, WritePriority},
};

/// Обработчик для отправки зашифрованных PING пакетов
pub struct PingSender {
    batch_writer: Arc<BatchWriter>,
    packet_processor: PhantomPacketProcessor,
    session: Arc<PhantomSession>,
    server_addr: std::net::SocketAddr,
    session_id: Vec<u8>,
    sequence: u64,
}

impl PingSender {
    pub fn new(
        batch_writer: Arc<BatchWriter>,
        session: Arc<PhantomSession>,
        server_addr: std::net::SocketAddr,
    ) -> Self {
        let session_id = session.session_id().to_vec();

        Self {
            batch_writer,
            packet_processor: PhantomPacketProcessor::new(),
            session,
            server_addr,
            session_id,
            sequence: 0,
        }
    }

    /// Создает зашифрованный PING пакет в правильном формате для сервера
    pub async fn create_encrypted_ping(&mut self) -> Result<Bytes, anyhow::Error> {
        self.sequence += 1;

        // Создаем PING пакет с шифрованием Phantom Protocol
        let ping_packet = match self.packet_processor.create_outgoing_vec(
            &self.session,
            0x01, // PING packet type
            &format!("PING #{} via BatchWriter", self.sequence).as_bytes()
        ) {
            Ok(packet) => packet,
            Err(e) => {
                error!("❌ Failed to create encrypted PING packet: {}", e);
                return Err(e.into());
            }
        };

        // Сервер ожидает данные в формате [u32 длина][данные...]
        // Но PhantomPacketProcessor уже создает полный пакет с заголовком!
        // Проверяем что получилось
        info!("📦 Created encrypted PING packet: {} bytes, sequence {}",
               ping_packet.len(), self.sequence);

        Ok(Bytes::from(ping_packet))
    }

    /// Отправляет один зашифрованный PING пакет
    pub async fn send_ping(&mut self) -> Result<(), anyhow::Error> {
        let encrypted_ping = self.create_encrypted_ping().await?;

        info!("📦 Created encrypted PING packet: {} bytes", encrypted_ping.len());

        // НЕ СОЗДАВАЙТЕ НОВОЕ СОЕДИНЕНИЕ!
        // Используйте BatchWriter, который уже зарегистрирован

        let ping_bytes = Bytes::from(encrypted_ping);

        match self.batch_writer.queue_write(
            self.server_addr,
            self.session_id.clone(),
            ping_bytes,
            WritePriority::Immediate,
            true, // flush_immediately = true
        ).await {
            Ok(_) => {
                info!("🏓 PING #{} queued via BatchWriter", self.sequence);
                Ok(())
            }
            Err(e) => {
                error!("❌ Failed to send PING via BatchWriter: {}", e);
                Err(e.into())
            }
        }
    }

    /// Отправляет несколько зашифрованных PING пакетов с интервалом
    pub async fn send_multiple_pings(
        &mut self,
        count: usize,
        interval_ms: u64,
    ) -> Result<(), anyhow::Error> {
        info!("🎯 Starting to send {} encrypted PING packets with interval {}ms...",
               count, interval_ms);

        let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));

        for i in 0..count {
            if i > 0 {
                interval.tick().await;
            }

            if let Err(e) = self.send_ping().await {
                error!("❌ Failed to send encrypted PING #{}/{}: {}", i + 1, count, e);
            }
        }

        info!("✅ Sent {} encrypted PING packets", count);
        Ok(())
    }

    /// Получает текущую последовательность
    pub fn current_sequence(&self) -> u64 {
        self.sequence
    }
}

/// Запускает задачу отправки зашифрованных PING пакетов
pub async fn start_ping_sender_task(
    batch_writer: Arc<BatchWriter>,
    session: Arc<PhantomSession>,
    server_addr: std::net::SocketAddr,
    ping_count: usize,
    ping_interval_ms: u64,
) -> Result<(), anyhow::Error> {
    let mut ping_sender = PingSender::new(
        batch_writer,
        session,
        server_addr,
    );

    ping_sender.send_multiple_pings(ping_count, ping_interval_ms).await
}

/// Тестовая функция для проверки создания пакетов
pub fn test_packet_creation(session: &PhantomSession) -> Result<(), anyhow::Error> {
    let processor = PhantomPacketProcessor::new();

    // Создаем тестовый PING пакет
    match processor.create_outgoing_vec(
        session,
        0x01,
        b"Test PING"
    ) {
        Ok(packet) => {
            info!("✅ Test packet created: {} bytes", packet.len());

            // Проверяем минимальный размер
            if packet.len() < 97 { // Минимальный размер Phantom пакета
                error!("❌ Packet too small: {} bytes, expected at least 97", packet.len());
                return Err(anyhow::anyhow!("Packet too small"));
            }

            // Проверяем magic bytes
            if packet.len() >= 2 && packet[0] == 0xAB && packet[1] == 0xCE {
                info!("✅ Magic bytes OK: 0xAB 0xCE");
            } else {
                error!("❌ Invalid magic bytes in packet");
                return Err(anyhow::anyhow!("Invalid magic bytes"));
            }

            Ok(())
        }
        Err(e) => {
            error!("❌ Failed to create test packet: {}", e);
            Err(e.into())
        }
    }
}