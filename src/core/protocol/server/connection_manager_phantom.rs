use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{Instant, Duration};
use tracing::{info, warn, debug};

use crate::core::protocol::phantom_crypto::keys::PhantomSession;
use crate::core::protocol::crypto::crypto_pool_phantom::PhantomCryptoPool;
use crate::core::protocol::server::session_manager_phantom::PhantomSessionManager;

const MAX_PACKET_SIZE: usize = 2 * 1024 * 1024; // 2 MB
const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct PhantomConnectionManager {
    active_connections: Arc<RwLock<HashMap<Vec<u8>, mpsc::Sender<()>>>>,
}

impl PhantomConnectionManager {
    pub fn new() -> Self {
        Self {
            active_connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn connection_exists(&self, session_id: &[u8]) -> bool {
        let connections = self.active_connections.read().await;
        connections.contains_key(session_id)
    }

    pub async fn register_connection(&self, session_id: Vec<u8>, shutdown_tx: mpsc::Sender<()>) {
        let mut connections = self.active_connections.write().await;
        connections.insert(session_id.clone(), shutdown_tx);
        info!("👻 Phantom connection registered for session: {}", hex::encode(session_id));
    }

    pub async fn unregister_connection(&self, session_id: &[u8]) {
        let mut connections = self.active_connections.write().await;
        connections.remove(session_id);
        info!("👻 Phantom connection unregistered for session: {}", hex::encode(session_id));
    }

    pub async fn force_disconnect(&self, session_id: &[u8]) {
        if let Some(shutdown_tx) = self.active_connections.write().await.remove(session_id) {
            let _ = shutdown_tx.send(()).await;
            info!("👻 Forced disconnect for phantom session: {}", hex::encode(session_id));
        }
    }

    pub async fn get_active_connections_count(&self) -> usize {
        let connections = self.active_connections.read().await;
        connections.len()
    }
}

pub async fn handle_phantom_client_connection(
    stream: TcpStream,
    peer: SocketAddr,
    session: Arc<PhantomSession>,
    phantom_crypto_pool: Arc<PhantomCryptoPool>,
    phantom_session_manager: Arc<PhantomSessionManager>,
    connection_manager: Arc<PhantomConnectionManager>,
) -> anyhow::Result<()> {
    let session_id = session.session_id();
    info!(target: "server", "👻 Starting phantom connection for session: {} from {}",
        hex::encode(session_id), peer);

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    let (reader, writer) = stream.into_split();

    // Регистрируем соединение
    connection_manager.register_connection(
        session_id.to_vec(),
        shutdown_tx
    ).await;

    // Запускаем writer task
    let writer_task = tokio::spawn(phantom_write_task(
        writer,
        session_id.to_vec(),
        peer,
    ));

    // Основной цикл обработки с поддержкой принудительного закрытия
    let process_result = tokio::select! {
        result = phantom_process_loop(
            reader,
            peer,
            session.clone(),
            phantom_crypto_pool,
            phantom_session_manager.clone(),
        ) => {
            result
        }
        _ = shutdown_rx.recv() => {
            info!(target: "server", "👻 {} forcibly disconnected by timeout", peer);
            Ok(())
        }
    };

    // Очистка
    writer_task.abort();
    phantom_session_manager.force_remove_session(session_id).await;
    connection_manager.unregister_connection(session_id).await;

    info!(target: "server", "👻 Phantom connection {} closed (session: {})",
        peer, hex::encode(session_id));

    process_result
}

async fn phantom_write_task(
    writer: tokio::net::tcp::OwnedWriteHalf,
    session_id: Vec<u8>,
    peer: SocketAddr,
) {
    let writer = writer;

    loop {
        match writer.writable().await {
            Ok(()) => {
                // Здесь будет логика отправки данных
                // Пока просто держим соединение
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => {
                warn!("👻 Phantom write task error for session {} from {}: {}",
                    hex::encode(&session_id), peer, e);
                break;
            }
        }
    }
}

async fn phantom_process_loop(
    reader: tokio::net::tcp::OwnedReadHalf,
    peer: SocketAddr,
    session: Arc<PhantomSession>,
    crypto_pool: Arc<PhantomCryptoPool>,
    session_manager: Arc<PhantomSessionManager>,
) -> anyhow::Result<()> {
    let mut last_activity = Instant::now();

    loop {
        // Проверяем таймаут неактивности
        if last_activity.elapsed() > INACTIVITY_TIMEOUT {
            warn!(target: "server", "👻 {} inactive for {:?}, closing connection",
                peer, last_activity.elapsed());
            break;
        }

        // Читаем данные с таймаутом
        let mut buffer = vec![0u8; 4096];
        match tokio::time::timeout(Duration::from_secs(5), reader.readable()).await {
            Ok(Ok(())) => {
                match reader.try_read(&mut buffer) {
                    Ok(0) => {
                        info!(target: "server", "👻 Phantom connection {} closed by peer", peer);
                        break;
                    }
                    Ok(n) => {
                        last_activity = Instant::now();
                        buffer.truncate(n);

                        // Обрабатываем пакет через фантомный криптопул
                        if let Err(e) = handle_phantom_packet(
                            &buffer,
                            peer,
                            &session,
                            &crypto_pool,
                            &session_manager,
                        ).await {
                            warn!("👻 Failed to handle phantom packet from {}: {}", peer, e);
                        }
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            continue;
                        }
                        info!(target: "server", "👻 Phantom connection {} read error: {}", peer, e);
                        break;
                    }
                }
            }
            Ok(Err(e)) => {
                info!(target: "server", "👻 Phantom connection {} error: {}", peer, e);
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

async fn handle_phantom_packet(
    data: &[u8],
    peer: SocketAddr,
    session: &Arc<PhantomSession>,
    crypto_pool: &Arc<PhantomCryptoPool>,
    session_manager: &Arc<PhantomSessionManager>,
) -> anyhow::Result<()> {
    let session_id = session.session_id();

    // Проверка размера пакета
    if data.len() > MAX_PACKET_SIZE {
        warn!("👻 Oversized phantom packet from {}: {} bytes", peer, data.len());
        return Ok(());
    }

    // Обработка heartbeat пакетов (упрощенная версия без heartbeat manager)
    if data.len() >= 1 && data[0] == 0x10 {
        debug!(target: "phantom_heartbeat",
            "👻 Heartbeat received from {} session: {}",
            peer, hex::encode(session_id));

        // Обновляем активность сессии
        session_manager.on_heartbeat_received(session_id).await;
        return Ok(());
    }

    // Декодируем и обрабатываем пакет через фантомный криптопул
    match crypto_pool.decrypt(session.clone(), data.to_vec()).await {
        Ok((packet_type, plaintext)) => {
            debug!(
                "👻 Successfully decrypted phantom packet from {}: type=0x{:02X}, size={} bytes",
                peer, packet_type, plaintext.len()
            );

            // Обработка расшифрованных данных
            process_decrypted_phantom_payload(
                packet_type,
                &plaintext,
                peer,
                session,
            ).await;
        }
        Err(e) => {
            warn!("👻 Failed to decrypt phantom packet from {}: {}", peer, e);
        }
    }

    Ok(())
}

async fn process_decrypted_phantom_payload(
    packet_type: u8,
    plaintext: &[u8],
    peer: SocketAddr,
    session: &Arc<PhantomSession>,
) {
    debug!(
        "👻 Processing phantom payload: type=0x{:02X}, size={} bytes, session={}, peer={}",
        packet_type,
        plaintext.len(),
        hex::encode(session.session_id()),
        peer
    );

    // Бизнес-логика обработки данных
    match packet_type {
        0x20 => { // Data packet
            info!("👻 Data packet received from {}: {} bytes",
                peer, plaintext.len());
            // Обработка данных
        }
        0x30 => { // Control packet
            info!("👻 Control packet received from {}", peer);
            // Обработка управления
        }
        _ => {
            info!("👻 Unknown packet type 0x{:02X} from {}", packet_type, peer);
        }
    }
}