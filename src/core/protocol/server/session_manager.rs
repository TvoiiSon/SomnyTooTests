use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{RwLock};
use tracing::{info, warn};

use crate::core::protocol::crypto::key_manager::session_keys::SessionKeys;
use crate::core::protocol::server::connection_manager::ConnectionManager;

pub struct Session {
    pub keys: Arc<SessionKeys>,
    pub addr: SocketAddr,
    pub created_at: std::time::Instant,
}

pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<Vec<u8>, Session>>>,
    connection_manager: Arc<ConnectionManager>,
}

impl SessionManager {
    pub fn new(connection_manager: Arc<ConnectionManager>) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            connection_manager,
        }
    }

    pub async fn register_session(&self, session_id: Vec<u8>, keys: Arc<SessionKeys>, addr: SocketAddr) {
        let session = Session {
            keys,
            addr,
            created_at: std::time::Instant::now(),
        };

        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.clone(), session);
        }

        info!("Client session registered: {} from {}", hex::encode(session_id.clone()), addr);
    }

    pub async fn unregister_session(&self, session_id: &[u8]) {
        self.force_remove_session(session_id).await;
    }

    pub async fn force_remove_session(&self, session_id: &[u8]) {
        let session_id_str = hex::encode(session_id);

        self.connection_manager.force_disconnect(session_id).await;

        {
            let mut sessions = self.sessions.write().await;
            sessions.remove(session_id);
        }

        info!("Client session fully removed: {}", session_id_str);
    }

    pub async fn session_exists(&self, session_id: &[u8]) -> bool {
        let sessions = self.sessions.read().await;
        sessions.contains_key(session_id)
    }

    pub async fn get_session_consistent(&self, session_id: &[u8]) -> Option<Arc<SessionKeys>> {
        let session_exists = self.session_exists(session_id).await;
        let connection_alive = self.connection_manager.connection_exists(session_id).await;

        if session_exists && connection_alive {
            let sessions = self.sessions.read().await;
            sessions.get(session_id).map(|session| session.keys.clone())
        } else if session_exists != connection_alive {
            warn!("Client session consistency issue detected for {}, forcing cleanup", hex::encode(session_id));
            self.force_remove_session(session_id).await;
            None
        } else {
            None
        }
    }

    pub async fn get_session(&self, session_id: &[u8]) -> Option<Arc<SessionKeys>> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).map(|session| session.keys.clone())
    }

    pub async fn is_connection_alive(&self, session_id: &[u8]) -> bool {
        self.connection_manager.connection_exists(session_id).await
    }

    pub async fn get_active_sessions(&self) -> Vec<Arc<SessionKeys>> {
        let sessions = self.sessions.read().await;
        sessions.values()
            .map(|session| session.keys.clone())
            .collect()
    }

    pub async fn get_consistent_sessions(&self) -> Vec<Arc<SessionKeys>> {
        let sessions = self.sessions.read().await;
        let mut consistent_sessions = Vec::new();

        for (session_id, session) in sessions.iter() {
            if self.connection_manager.connection_exists(session_id).await {
                consistent_sessions.push(session.keys.clone());
            }
        }

        consistent_sessions
    }

    pub async fn check_session_reuse(_session_id: &[u8]) -> bool {
        false
    }

    pub async fn check_consistency(&self) -> usize {
        let sessions = self.sessions.read().await;
        let mut inconsistent_count = 0;

        for session_id in sessions.keys() {
            let connection_exists = self.connection_manager.connection_exists(session_id).await;

            if !connection_exists {
                inconsistent_count += 1;
                warn!("Client inconsistent session detected: {}", hex::encode(session_id));
            }
        }

        inconsistent_count
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        let connection_manager = Arc::new(ConnectionManager::new());
        Self::new(connection_manager)
    }
}