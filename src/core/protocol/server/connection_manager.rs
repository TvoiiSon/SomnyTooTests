use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{Instant, Duration};
use tracing::{info, warn, error, debug};
use anyhow::Result;

use crate::core::protocol::packets::processor::dispatcher::{Dispatcher, Work};
use crate::core::protocol::crypto::key_manager::session_keys::SessionKeys;
use crate::core::protocol::packets::encoder::frame_writer::write_frame;
use crate::core::protocol::packets::decoder::frame_reader::read_frame;
use crate::core::protocol::server::session_manager::SessionManager;

const LARGE_THRESHOLD: usize = 16 * 1024;
const MAX_PACKET_SIZE: usize = 2 * 1024 * 1024;
const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct ConnectionManager {
    active_connections: Arc<RwLock<HashMap<Vec<u8>, mpsc::Sender<Vec<u8>>>>>,
}

#[derive(Debug)]
pub struct ConnectionStats {
    pub total_connections: usize,
    pub session_ids: Vec<Vec<u8>>,
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            active_connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn connection_exists(&self, session_id: &[u8]) -> bool {
        let connections = self.active_connections.read().await;
        connections.contains_key(session_id)
    }

    pub async fn get_connection_stats(&self) -> ConnectionStats {
        let connections = self.active_connections.read().await;
        ConnectionStats {
            total_connections: connections.len(),
            session_ids: connections.keys().cloned().collect(),
        }
    }

    pub async fn register_connection(&self, session_id: Vec<u8>, out_tx: mpsc::Sender<Vec<u8>>) {
        let session_id_clone = session_id.clone();
        let mut connections = self.active_connections.write().await;
        connections.insert(session_id, out_tx);
        info!("Client connection registered for session: {}", hex::encode(&session_id_clone));
    }

    pub async fn unregister_connection(&self, session_id: &[u8]) {
        let mut connections = self.active_connections.write().await;
        connections.remove(session_id);
        info!("Client connection unregistered for session: {}", hex::encode(session_id));
    }

    pub async fn force_disconnect(&self, session_id: &[u8]) {
        if self.active_connections.write().await.remove(session_id).is_some() {
            info!("Client forced disconnect for session: {}", hex::encode(session_id));
        }
    }

    pub async fn send_packet(&self, session_id: &[u8], packet: Vec<u8>) -> Result<()> {
        let connections = self.active_connections.read().await;

        if let Some(sender) = connections.get(session_id) {
            sender.send(packet)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to send packet: {}", e))
        } else {
            Err(anyhow::anyhow!("No active connection for session: {}", hex::encode(session_id)))
        }
    }

    pub async fn get_connection_info(&self) -> Vec<String> {
        let connections = self.active_connections.read().await;
        connections.keys()
            .map(|session_id| hex::encode(session_id))
            .collect()
    }
}

pub async fn handle_server_connection(
    stream: TcpStream,
    peer: SocketAddr,
    session_keys: Arc<SessionKeys>,
    dispatcher: Arc<Dispatcher>,
    session_manager: Arc<SessionManager>,
    connection_manager: Arc<ConnectionManager>,
) -> Result<()> {
    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(32768);

    connection_manager.register_connection(
        session_keys.session_id.to_vec(),
        out_tx.clone()
    ).await;

    session_manager.register_session(
        session_keys.session_id.to_vec(),
        Arc::clone(&session_keys),
        peer,
    ).await;

    let (reader, writer) = stream.into_split();

    let writer_task = tokio::spawn(write_task(writer, out_rx));
    let reader_task = tokio::spawn(read_task(
        reader,
        peer,
        session_keys.clone(),
        dispatcher,
        connection_manager.clone(),
    ));

    // Ждем завершения любой из задач
    tokio::select! {
        result = reader_task => {
            if let Err(e) = result {
                error!("Reader task error: {}", e);
            }
        }
        result = writer_task => {
            if let Err(e) = result {
                error!("Writer task error: {}", e);
            }
        }
    }

    // Очищаем ресурсы
    session_manager.force_remove_session(&session_keys.session_id).await;
    connection_manager.unregister_connection(&session_keys.session_id).await;

    info!("Connection with {} closed", peer);
    Ok(())
}

async fn write_task(writer: tokio::net::tcp::OwnedWriteHalf, mut out_rx: mpsc::Receiver<Vec<u8>>) {
    let mut writer = writer;

    while let Some(packet) = out_rx.recv().await {
        if let Err(e) = write_frame(&mut writer, &packet).await {
            error!("Failed to write frame: {}", e);
            break;
        }
    }
}

async fn read_task(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    peer: SocketAddr,
    session_keys: Arc<SessionKeys>,
    dispatcher: Arc<Dispatcher>,
    connection_manager: Arc<ConnectionManager>,
) -> Result<()> {
    let mut total_bytes_received = 0;
    let start_time = Instant::now();
    let mut last_activity = Instant::now();

    loop {
        // Проверяем таймаут неактивности
        if last_activity.elapsed() > INACTIVITY_TIMEOUT {
            warn!("Connection inactive for {:?}, closing", last_activity.elapsed());
            break;
        }

        // Читаем фрейм с таймаутом
        match tokio::time::timeout(Duration::from_secs(30), read_frame(&mut reader)).await {
            Ok(Ok(frame)) => {
                last_activity = Instant::now();

                if let Err(e) = handle_incoming_frame(
                    &frame,
                    peer,
                    &session_keys,
                    &dispatcher,
                    &connection_manager,
                    &mut total_bytes_received,
                    start_time,
                ).await {
                    error!("Error handling frame: {}", e);
                    break;
                }
            }
            Ok(Err(e)) => {
                info!("Disconnected: {}", e);
                break;
            }
            Err(_) => {
                // Таймаут чтения - продолжаем цикл
                continue;
            }
        }
    }

    Ok(())
}

async fn handle_incoming_frame(
    frame: &[u8],
    peer: SocketAddr,
    session_keys: &Arc<SessionKeys>,
    dispatcher: &Arc<Dispatcher>,
    connection_manager: &Arc<ConnectionManager>,
    total_bytes_received: &mut usize,
    start_time: Instant,
) -> Result<()> {
    // Проверка размера пакета
    if frame.len() > MAX_PACKET_SIZE {
        return Err(anyhow::anyhow!("Oversized packet: {} bytes", frame.len()));
    }

    *total_bytes_received += frame.len();

    // Проверка bandwidth
    let elapsed = start_time.elapsed().as_secs_f64();
    if elapsed > 0.0 {
        let bandwidth = *total_bytes_received as f64 / elapsed;
        if bandwidth > 1024.0 * 1024.0 {
            return Err(anyhow::anyhow!("Bandwidth limit exceeded: {:.2} MB/s", bandwidth / 1024.0 / 1024.0));
        }
    }

    // Обработка heartbeat
    if frame.len() >= 1 && frame[0] == 0x10 {
        debug!("Heartbeat received from {}", peer);
        return Ok(());
    }

    // Отправка на обработку в dispatcher
    let priority = crate::core::protocol::packets::processor::priority::determine_priority(frame);
    let is_large = frame.len() > LARGE_THRESHOLD;

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();

    let work = Work {
        ctx: Arc::clone(session_keys),
        raw_payload: frame.to_vec(),
        client_ip: peer,
        reply: reply_tx,
        received_at: Instant::now(),
        priority,
        is_large,
    };

    if dispatcher.submit(work).await.is_err() {
        return Err(anyhow::anyhow!("Dispatcher busy"));
    }

    // Ждем ответа от обработчика
    match tokio::time::timeout(Duration::from_secs(10), reply_rx).await {
        Ok(Ok(response)) => {
            if !response.is_empty() {
                // Отправляем ответ только если он не пустой
                if let Err(e) = connection_manager.send_packet(&session_keys.session_id, response).await {
                    error!("Failed to send response: {}", e);
                }
            }
        }
        Ok(Err(_)) => {
            error!("Handler channel closed");
        }
        Err(_) => {
            error!("Handler timeout");
        }
    }

    Ok(())
}