use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::{mpsc, RwLock};
use tracing::{info};

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