use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration, Instant};
use tracing::{info, warn, error, debug};

use crate::core::protocol::phantom_crypto::core::handshake::{perform_phantom_handshake, HandshakeRole};
use crate::config::PhantomConfig;
// Добавляем импорт PhantomPacketService
use crate::core::protocol::packets::processor::packet_service::PhantomPacketService;

pub async fn handle_phantom_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    phantom_config: PhantomConfig,
    session_manager: Arc<crate::core::protocol::server::session_manager_phantom::PhantomSessionManager>,
    connection_manager: Arc<crate::core::protocol::server::connection_manager_phantom::PhantomConnectionManager>,
    crypto_pool: Arc<crate::core::protocol::crypto::crypto_pool_phantom::PhantomCryptoPool>,
    packet_service: Arc<PhantomPacketService>,
) -> anyhow::Result<()> {
    let connection_start = Instant::now();
    info!(target: "server", "👻 {} attempting phantom connection", peer);

    // Выполняем фантомный handshake с таймаутом
    let handshake_start = Instant::now();
    let handshake_result = match timeout(
        Duration::from_secs(30),
        perform_phantom_handshake(&mut stream, HandshakeRole::Server)
    ).await {
        Ok(Ok(result)) => {
            let handshake_time = handshake_start.elapsed();
            info!(target: "server",
                "👻 Phantom handshake successful for {} in {:?}, session: {}",
                peer, handshake_time, hex::encode(&result.session.session_id()));
            result
        },
        Ok(Err(e)) => {
            let handshake_time = handshake_start.elapsed();
            warn!(target: "server",
                "👻 Phantom handshake failed for {} after {:?}: {}",
                peer, handshake_time, e);
            return Ok(());
        }
        Err(_) => {
            error!(target: "server", "👻 Phantom handshake timeout for {}", peer);
            return Ok(());
        }
    };

    // Проверяем конфигурацию фантомной системы
    if let Err(e) = phantom_config.validate() {
        error!("👻 Invalid phantom configuration: {}", e);
        return Ok(());
    }

    // Проверяем аппаратную аутентификацию если включена
    if phantom_config.should_use_hardware_auth() {
        info!("👻 Hardware authentication enabled for session: {}",
            hex::encode(&handshake_result.session.session_id()));
    }

    // Регистрируем фантомную сессию
    let phantom_session = Arc::new(handshake_result.session);
    let session_id = phantom_session.session_id();


    info!(target: "server", "💓 Heartbeat started for session: {} from {}",
        hex::encode(&session_id), peer);

    // Запускаем обработку соединения через фантомный менеджер соединений
    let connection_result = crate::core::protocol::server::connection_manager_phantom::handle_phantom_client_connection(
        stream,
        peer,
        phantom_session.clone(),
        crypto_pool,
        session_manager.clone(),
        connection_manager.clone(),
        packet_service.clone(), // Передаем packet_service
    ).await;

    // Ждем завершения обработки соединения
    let connection_handler_result = match connection_result {
        Ok(()) => {
            debug!("💓 Connection handler completed successfully for session: {}",
                hex::encode(&session_id));
            Ok(())
        }
        Err(e) => {
            error!("💓 Connection handler error for session {}: {}",
                hex::encode(&session_id), e);
            Err(e)
        }
    };

    // Останавливаем heartbeat для этой сессии
    info!(target: "server", "💓 Heartbeat stopped for session: {}", hex::encode(&session_id));

    // Логируем время соединения
    let total_connection_time = connection_start.elapsed();
    info!(target: "server",
        "👻 {} phantom connection closed after {:?}, session: {}",
        peer, total_connection_time, hex::encode(session_id));

    connection_handler_result
}