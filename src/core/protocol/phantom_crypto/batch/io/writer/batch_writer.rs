use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn, error};
use bytes::Bytes;
use crate::core::protocol::packets::frame_writer;
use crate::core::protocol::phantom_crypto::batch::types::error::BatchError;

#[derive(Debug, Clone, Copy)]
pub enum WritePriority {
    Immediate,
    Normal,
    Low,
}

#[derive(Debug, Clone)]
pub struct BatchWriterConfig {
    pub batch_size: usize,
    pub max_batch_size: usize,
    pub flush_interval_ms: u64,
    pub max_buffer_size: usize,
    pub write_timeout_ms: u64,
    pub retry_count: usize,
    pub retry_delay_ms: u64,
}

impl Default for BatchWriterConfig {
    fn default() -> Self {
        Self {
            batch_size: 16,
            max_batch_size: 64,
            flush_interval_ms: 100,
            max_buffer_size: 1024 * 1024,
            write_timeout_ms: 5000,
            retry_count: 3,
            retry_delay_ms: 100,
        }
    }
}

#[derive(Debug)]
pub struct BatchWriterStats {
    pub total_writes: u64,
    pub bytes_per_second: u64,
    pub writes_per_second: u64,
    pub last_update: Instant,
}

#[derive(Debug)]
pub enum BatchWriterEvent {
    WriteCompleted {
        destination_addr: std::net::SocketAddr,
        batch_id: u64,
        bytes_written: usize,
        write_time: Duration,
    },
    WriteError {
        destination_addr: std::net::SocketAddr,
        error: String,
    },
    BufferFull {
        destination_addr: std::net::SocketAddr,
        buffer_size: usize,
    },
    StatisticsUpdate {
        stats: BatchWriterStats,
    },
}

struct ConnectionState {
    writer: Box<dyn AsyncWrite + Unpin + Send>,
    buffer: Vec<Bytes>,
    buffer_size: usize,
    last_flush: Instant,
    session_id: Vec<u8>,
}

pub struct BatchWriter {
    connections: Arc<Mutex<std::collections::HashMap<std::net::SocketAddr, ConnectionState>>>,
    config: BatchWriterConfig,
    events_tx: mpsc::Sender<BatchWriterEvent>,
    next_batch_id: std::sync::atomic::AtomicU64,
}

impl BatchWriter {
    pub fn new(config: BatchWriterConfig) -> (Self, mpsc::Receiver<BatchWriterEvent>) {
        let (events_tx, events_rx) = mpsc::channel(100);

        let writer = Self {
            connections: Arc::new(Mutex::new(std::collections::HashMap::new())),
            config,
            events_tx,
            next_batch_id: std::sync::atomic::AtomicU64::new(1),
        };

        // Запускаем фоновую задачу для периодической отправки
        let writer_clone = writer.clone();
        tokio::spawn(async move {
            writer_clone.background_flush_task().await;
        });

        (writer, events_rx)
    }

    pub fn clone(&self) -> Self {
        Self {
            connections: Arc::clone(&self.connections),
            config: self.config.clone(),
            events_tx: self.events_tx.clone(),
            next_batch_id: std::sync::atomic::AtomicU64::new(
                self.next_batch_id.load(std::sync::atomic::Ordering::Relaxed)
            ),
        }
    }

    pub async fn register_connection(
        &self,
        addr: std::net::SocketAddr,
        session_id: Vec<u8>,
        writer: Box<dyn AsyncWrite + Unpin + Send>,
    ) -> Result<(), BatchError> {
        let mut connections = self.connections.lock().await;

        let session_id_clone = session_id.clone();

        connections.insert(addr, ConnectionState {
            writer,
            buffer: Vec::with_capacity(self.config.batch_size),
            buffer_size: 0,
            last_flush: Instant::now(),
            session_id,
        });

        info!("📤 BatchWriter registered connection: {} session: {}",
              addr, hex::encode(&session_id_clone));

        Ok(())
    }

    pub async fn queue_write(
        &self,
        addr: std::net::SocketAddr,
        session_id: Vec<u8>,
        data: Bytes,
        priority: WritePriority,
        flush_immediately: bool,
    ) -> Result<(), BatchError> {
        let mut connections = self.connections.lock().await;

        let connection = match connections.get_mut(&addr) {
            Some(conn) => {
                // Проверяем session_id
                if conn.session_id != session_id {
                    return Err(BatchError::ProcessingFailed(
                        format!("Session ID mismatch for {}", addr)
                    ));
                }
                conn
            }
            None => {
                return Err(BatchError::ProcessingFailed(
                    format!("No registered connection for {}", addr)
                ));
            }
        };

        // Проверяем размер буфера
        if connection.buffer_size + data.len() > self.config.max_buffer_size {
            let _ = self.events_tx.send(BatchWriterEvent::BufferFull {
                destination_addr: addr,
                buffer_size: connection.buffer_size,
            }).await;

            return Err(BatchError::BufferFull(
                format!("Buffer full for {}: {} bytes", addr, connection.buffer_size)
            ));
        }

        // Добавляем в буфер
        connection.buffer.push(data.clone());
        connection.buffer_size += data.len();

        debug!("📥 Queued write for {}: {} bytes (total buffer: {} bytes)",
               addr, data.len(), connection.buffer_size);

        // Немедленная отправка если нужно
        if flush_immediately || matches!(priority, WritePriority::Immediate) {
            self.flush_connection(addr, connection).await?;
        }
        // Отправка если достигли размера батча
        else if connection.buffer.len() >= self.config.batch_size {
            self.flush_connection(addr, connection).await?;
        }

        Ok(())
    }

    async fn flush_connection(
        &self,
        addr: std::net::SocketAddr,
        connection: &mut ConnectionState,
    ) -> Result<(), BatchError> {
        if connection.buffer.is_empty() {
            return Ok(());
        }

        let batch_id = self.next_batch_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let start_time = Instant::now();

        // КРИТИЧЕСКИ ВАЖНО: Каждый пакет должен иметь заголовок длины
        let mut total_bytes_written = 0;

        for data in &connection.buffer {
            // Добавляем заголовок длины [u32 длина][данные...]
            let length = data.len() as u32;
            let header = length.to_be_bytes();

            // Отправляем заголовок
            if let Err(e) = connection.writer.write_all(&header).await {
                error!("❌ Failed to write header for {}: {}", addr, e);
                return Err(BatchError::ProcessingFailed(e.to_string()));
            }
            total_bytes_written += 4;

            // Отправляем данные
            if let Err(e) = connection.writer.write_all(data).await {
                error!("❌ Failed to write data for {}: {}", addr, e);
                return Err(BatchError::ProcessingFailed(e.to_string()));
            }
            total_bytes_written += data.len();
        }

        // Flush
        if let Err(e) = connection.writer.flush().await {
            error!("❌ Flush error for {}: {}", addr, e);
            return Err(BatchError::ProcessingFailed(e.to_string()));
        }

        let write_time = start_time.elapsed();

        // Отправляем событие
        let _ = self.events_tx.send(BatchWriterEvent::WriteCompleted {
            destination_addr: addr,
            batch_id,
            bytes_written: total_bytes_written,
            write_time,
        }).await;

        // Очищаем буфер
        connection.buffer.clear();
        connection.buffer_size = 0;
        connection.last_flush = Instant::now();

        info!("✅ Batch #{} sent to {}: {} frames, {} bytes total",
          batch_id, addr, connection.buffer.len(), total_bytes_written);

        Ok(())
    }

    async fn background_flush_task(&self) {
        let mut interval = tokio::time::interval(Duration::from_millis(self.config.flush_interval_ms));

        loop {
            interval.tick().await;

            let mut connections = self.connections.lock().await;
            let mut addrs_to_remove = Vec::new();

            for (addr, connection) in connections.iter_mut() {
                // Проверяем время с последней отправки
                if connection.last_flush.elapsed() > Duration::from_millis(self.config.flush_interval_ms)
                    && !connection.buffer.is_empty() {

                    if let Err(e) = self.flush_connection(*addr, connection).await {
                        error!("❌ Background flush failed for {}: {}", addr, e);
                        addrs_to_remove.push(*addr);
                    }
                }
            }

            // Удаляем нерабочие соединения
            for addr in addrs_to_remove {
                connections.remove(&addr);
                warn!("🗑️ Removed broken connection: {}", addr);
            }
        }
    }

    pub async fn unregister_connection(&self, addr: std::net::SocketAddr) {
        if self.connections.lock().await.remove(&addr).is_some() {
            info!("📭 BatchWriter unregistered connection: {}", addr);
        }
    }
}

impl Clone for BatchWriter {
    fn clone(&self) -> Self {
        Self {
            connections: Arc::clone(&self.connections),
            config: self.config.clone(),
            events_tx: self.events_tx.clone(),
            next_batch_id: std::sync::atomic::AtomicU64::new(
                self.next_batch_id.load(std::sync::atomic::Ordering::Relaxed)
            ),
        }
    }
}