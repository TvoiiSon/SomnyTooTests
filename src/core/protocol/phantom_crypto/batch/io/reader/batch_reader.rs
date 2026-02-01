use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn, error};

use crate::core::protocol::phantom_crypto::batch::types::error::BatchError;

#[derive(Debug, Clone)]
pub struct BatchReaderConfig {
    pub batch_size: usize,
    pub max_frame_size: usize,
    pub read_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub buffer_size: usize,
}

impl Default for BatchReaderConfig {
    fn default() -> Self {
        Self {
            batch_size: 32,
            max_frame_size: 65536,
            read_timeout_ms: 30000,
            idle_timeout_ms: 60000,
            buffer_size: 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BatchFrame {
    pub session_id: Vec<u8>,
    pub data: Vec<u8>,
    pub received_at: Instant,
}

#[derive(Debug)]
pub enum BatchReaderEvent {
    BatchReady {
        batch_id: u64,
        frames: Vec<BatchFrame>,
        source_addr: std::net::SocketAddr,
        received_at: Instant,
    },
    ConnectionClosed {
        source_addr: std::net::SocketAddr,
        reason: String,
    },
    ReadError {
        source_addr: std::net::SocketAddr,
        error: String,
    },
    StatisticsUpdate {
        stats: BatchReaderStats,
    },
}

#[derive(Debug, Clone)]
pub struct BatchReaderStats {
    pub total_frames_read: u64,
    pub total_batches_processed: u64,
    pub bytes_read: u64,
    pub frames_per_second: u64,
    pub bytes_per_second: u64,
    pub avg_batch_size: f64,
    pub read_errors: u64,
    pub last_update: Instant,
}

impl Default for BatchReaderStats {
    fn default() -> Self {
        Self {
            total_frames_read: 0,
            total_batches_processed: 0,
            bytes_read: 0,
            frames_per_second: 0,
            bytes_per_second: 0,
            avg_batch_size: 0.0,
            read_errors: 0,
            last_update: Instant::now(),
        }
    }
}

struct ConnectionReader {
    reader: Box<dyn AsyncRead + Unpin + Send>,
    #[allow(dead_code)] // Добавляем атрибут для buffer
    buffer: Vec<u8>,
    last_activity: Instant,
    session_id: Vec<u8>,
}

pub struct BatchReader {
    connections: Arc<Mutex<std::collections::HashMap<std::net::SocketAddr, ConnectionReader>>>,
    config: BatchReaderConfig,
    events_tx: mpsc::Sender<BatchReaderEvent>,
    stats: Arc<tokio::sync::Mutex<BatchReaderStats>>,
    next_batch_id: std::sync::atomic::AtomicU64,
}

impl BatchReader {
    pub fn new(config: BatchReaderConfig, events_tx: mpsc::Sender<BatchReaderEvent>) -> Self {
        let stats = Arc::new(tokio::sync::Mutex::new(BatchReaderStats::default()));

        let reader = Self {
            connections: Arc::new(Mutex::new(std::collections::HashMap::new())),
            config,
            events_tx,
            stats,
            next_batch_id: std::sync::atomic::AtomicU64::new(1),
        };

        // Запускаем фоновую задачу для чтения
        let reader_clone = reader.clone();
        tokio::spawn(async move {
            reader_clone.background_read_task().await;
        });

        reader
    }

    pub fn clone(&self) -> Self {
        Self {
            connections: Arc::clone(&self.connections),
            config: self.config.clone(),
            events_tx: self.events_tx.clone(),
            stats: Arc::clone(&self.stats),
            next_batch_id: std::sync::atomic::AtomicU64::new(
                self.next_batch_id.load(std::sync::atomic::Ordering::Relaxed)
            ),
        }
    }

    pub async fn register_connection(
        &self,
        addr: std::net::SocketAddr,
        session_id: Vec<u8>,
        reader: Box<dyn AsyncRead + Unpin + Send>,
    ) -> Result<(), BatchError> {
        let mut connections = self.connections.lock().await;

        connections.insert(addr, ConnectionReader {
            reader,
            buffer: Vec::with_capacity(self.config.buffer_size),
            last_activity: Instant::now(),
            session_id: session_id.clone(),
        });

        info!("📥 BatchReader registered connection: {} session: {}",
              addr, hex::encode(&session_id));

        Ok(())
    }

    async fn read_frame_from_connection(
        &self,
        _addr: std::net::SocketAddr,
        connection: &mut ConnectionReader,
    ) -> Result<Option<BatchFrame>, BatchError> {
        let mut header = [0u8; 4];

        // Читаем заголовок
        match tokio::time::timeout(
            Duration::from_millis(self.config.read_timeout_ms),
            connection.reader.read_exact(&mut header)
        ).await {
            Ok(Ok(_)) => {
                // Продолжаем
            }
            Ok(Err(e)) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    return Ok(None); // Соединение закрыто
                }
                return Err(BatchError::IoError(format!("Header read error: {}", e)));
            }
            Err(_) => {
                return Err(BatchError::IoError("Read timeout".to_string()));
            }
        }

        let length = u32::from_be_bytes(header) as usize;

        if length > self.config.max_frame_size {
            return Err(BatchError::InvalidData(format!(
                "Frame too large: {} > {}",
                length, self.config.max_frame_size
            )));
        }

        if length == 0 {
            return Ok(Some(BatchFrame {
                session_id: connection.session_id.clone(),
                data: Vec::new(),
                received_at: Instant::now(),
            }));
        }

        // Читаем данные
        let mut data = vec![0u8; length];
        match tokio::time::timeout(
            Duration::from_millis(self.config.read_timeout_ms),
            connection.reader.read_exact(&mut data)
        ).await {
            Ok(Ok(_)) => {
                connection.last_activity = Instant::now();

                Ok(Some(BatchFrame {
                    session_id: connection.session_id.clone(),
                    data,
                    received_at: Instant::now(),
                }))
            }
            Ok(Err(e)) => {
                Err(BatchError::IoError(format!("Data read error: {}", e)))
            }
            Err(_) => {
                Err(BatchError::IoError("Data read timeout".to_string()))
            }
        }
    }

    async fn background_read_task(&self) {
        let mut interval = tokio::time::interval(Duration::from_millis(10));

        loop {
            interval.tick().await;

            let mut connections = self.connections.lock().await;
            let mut addrs_to_remove = Vec::new();
            let mut frames_batch = Vec::new();
            let mut current_addr = None;

            for (addr, connection) in connections.iter_mut() {
                current_addr = Some(*addr);

                // Проверяем таймаут бездействия
                if connection.last_activity.elapsed() > Duration::from_millis(self.config.idle_timeout_ms) {
                    warn!("⏰ Idle timeout for {}", addr);
                    addrs_to_remove.push(*addr);
                    continue;
                }

                // Пытаемся прочитать фрейм
                match self.read_frame_from_connection(*addr, connection).await {
                    Ok(Some(frame)) => {
                        // Сохраняем длину данных перед перемещением frame
                        let data_len = frame.data.len() as u64;

                        frames_batch.push(frame);

                        // Обновляем статистику
                        let mut stats = self.stats.lock().await;
                        stats.total_frames_read += 1;
                        stats.bytes_read += data_len;
                    }
                    Ok(None) => {
                        // Соединение закрыто
                        addrs_to_remove.push(*addr);
                        debug!("📭 Connection closed by peer: {}", addr);
                    }
                    Err(e) => {
                        error!("❌ Read error for {}: {}", addr, e);
                        addrs_to_remove.push(*addr);

                        // Обновляем статистику ошибок
                        let mut stats = self.stats.lock().await;
                        stats.read_errors += 1;
                    }
                }

                // Если набрали батч, отправляем
                if frames_batch.len() >= self.config.batch_size {
                    if let Some(addr) = current_addr {
                        self.send_batch(addr, frames_batch.clone()).await;
                        frames_batch.clear();
                    }
                }
            }

            // Отправляем оставшиеся фреймы
            if !frames_batch.is_empty() {
                if let Some(addr) = current_addr {
                    self.send_batch(addr, frames_batch.clone()).await;
                }
            }

            // Удаляем нерабочие соединения
            for addr in addrs_to_remove {
                if let Some(_connection) = connections.remove(&addr) {
                    let _ = self.events_tx.send(BatchReaderEvent::ConnectionClosed {
                        source_addr: addr,
                        reason: "Connection error or timeout".to_string(),
                    }).await;

                    info!("🗑️ BatchReader removed connection: {}", addr);
                }
            }

            // Обновляем статистику
            self.update_stats().await;
        }
    }

    async fn send_batch(&self, source_addr: std::net::SocketAddr, frames: Vec<BatchFrame>) {
        if frames.is_empty() {
            return;
        }

        let batch_id = self.next_batch_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Клонируем фреймы для отправки
        let frames_clone = frames.iter().cloned().collect::<Vec<_>>();

        let _ = self.events_tx.send(BatchReaderEvent::BatchReady {
            batch_id,
            frames: frames_clone,
            source_addr,
            received_at: Instant::now(),
        }).await;

        // Обновляем статистику
        let mut stats = self.stats.lock().await;
        stats.total_batches_processed += 1;
        stats.avg_batch_size = (stats.avg_batch_size * (stats.total_batches_processed as f64 - 1.0)
            + frames.len() as f64) / stats.total_batches_processed as f64;
    }

    async fn update_stats(&self) {
        let mut stats = self.stats.lock().await;
        let now = Instant::now();
        let elapsed = now.duration_since(stats.last_update);

        if elapsed.as_secs() > 0 {
            stats.frames_per_second = stats.total_frames_read / elapsed.as_secs();
            stats.bytes_per_second = stats.bytes_read / elapsed.as_secs();
            stats.last_update = now;

            // Отправляем обновление статистики
            let _ = self.events_tx.send(BatchReaderEvent::StatisticsUpdate {
                stats: stats.clone(),
            }).await;
        }
    }

    pub async fn unregister_connection(&self, addr: std::net::SocketAddr) {
        if self.connections.lock().await.remove(&addr).is_some() {
            info!("📭 BatchReader unregistered connection: {}", addr);
        }
    }
}