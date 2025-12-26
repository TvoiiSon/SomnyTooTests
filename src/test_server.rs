use tracing::{info};
use std::sync::Arc;
use tokio::net::TcpListener;

use crate::core::protocol::server::connection_manager::ConnectionManager;
use crate::core::protocol::server::tcp_server::handle_connection;
use crate::core::protocol::packets::processor::dispatcher::Dispatcher;
use crate::core::protocol::crypto::crypto_pool::CryptoPool;
use crate::core::protocol::packets::processor::packet_service::PacketService;
use crate::core::protocol::server::session_manager::SessionManager;

pub struct TestServer {
    pub dispatcher: Arc<Dispatcher>,
    pub crypto_pool: CryptoPool,
    pub addr: String,
    pub session_manager: Arc<SessionManager>,
}

impl TestServer {
    pub async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        info!(target: "test_server", "listening on {}", addr);

        let crypto_pool = CryptoPool::spawn(8);
        let connection_manager = Arc::new(ConnectionManager::new());
        let session_manager = Arc::new(SessionManager::new(connection_manager.clone()));
        let packet_service = PacketService::new();
        let dispatcher = Arc::new(Dispatcher::spawn(20, packet_service));

        let dispatcher_clone = dispatcher.clone();
        let session_manager_clone = session_manager.clone();
        let connection_manager_clone = connection_manager.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let dispatcher = dispatcher_clone.clone();
                        let session_manager = session_manager_clone.clone();
                        let connection_manager = connection_manager_clone.clone();

                        tokio::spawn(async move {
                            info!(target: "test_server", "Connection from {}", peer);
                            let _ = handle_connection(stream, peer, dispatcher, session_manager, connection_manager).await;
                            info!(target: "test_server", "Disconnected {}", peer);
                        });
                    }
                    Err(e) => {
                        info!(target: "test_server", "Accept error: {}", e);
                        break;
                    }
                }
            }
        });

        Self {
            dispatcher,
            crypto_pool,
            addr,
            session_manager,
        }
    }
}