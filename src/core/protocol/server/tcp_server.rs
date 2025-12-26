use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tracing::{info, warn, error};

use crate::core::protocol::packets::processor::dispatcher::Dispatcher;
use crate::core::protocol::server::session_manager::SessionManager;
use crate::core::protocol::server::connection_manager::ConnectionManager;
use crate::core::protocol::crypto::handshake::handshake::{perform_handshake, HandshakeRole};

pub async fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    dispatcher: Arc<Dispatcher>,
    session_manager: Arc<SessionManager>,
    connection_manager: Arc<ConnectionManager>,
) -> anyhow::Result<()> {
    info!("{} connected to client server", peer);

    // На клиенте используем роль Client для handshake с сервером
    let handshake_result = match timeout(
        Duration::from_secs(30),
        perform_handshake(&mut stream, HandshakeRole::Client)
    ).await {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            warn!("Client handshake failed for {}: {}", peer, e);
            return Ok(());
        }
        Err(_) => {
            error!("Client handshake timeout for {}", peer);
            return Ok(());
        }
    };

    if SessionManager::check_session_reuse(&handshake_result.session_keys.session_id).await {
        warn!("Client session reuse detected for {}: {}", peer, hex::encode(handshake_result.session_keys.session_id));
        return Ok(());
    }

    let result = super::connection_manager::handle_server_connection(
        stream,
        peer,
        Arc::new(handshake_result.session_keys.clone()),
        dispatcher,
        session_manager.clone(),
        connection_manager,
    ).await;

    info!("Connection with {} finished", peer);
    result
}

pub fn register_metrics(_registry: &prometheus::Registry) -> anyhow::Result<()> {
    Ok(())
}