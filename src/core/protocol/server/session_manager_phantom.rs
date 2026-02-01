use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use crate::core::protocol::phantom_crypto::core::keys::PhantomSession;

pub struct PhantomSessionManager {
    sessions: Arc<RwLock<HashMap<Vec<u8>, Arc<PhantomSession>>>>,
}

impl PhantomSessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_session(&self, session_id: &[u8], session: Arc<PhantomSession>) {
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.to_vec(), session);
    }

    pub async fn get_session(&self, session_id: &[u8]) -> Option<Arc<PhantomSession>> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).cloned()
    }

    pub async fn session_exists(&self, session_id: &[u8]) -> bool {
        let sessions = self.sessions.read().await;
        sessions.contains_key(session_id)
    }

    pub async fn remove_session(&self, session_id: &[u8]) {
        if self.sessions.write().await.remove(session_id).is_some() {
            info!("👻 Phantom session removed: {}", hex::encode(session_id));
        }
    }
}

impl Default for PhantomSessionManager {
    fn default() -> Self {
        Self::new()
    }
}