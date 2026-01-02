use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use tracing::{info, warn};

use crate::core::protocol::phantom_crypto::keys::PhantomSession;
use crate::core::protocol::server::connection_manager_phantom::PhantomConnectionManager;

pub struct PhantomSessionEntry {
    pub session: Arc<PhantomSession>,
    pub addr: SocketAddr,
    pub created_at: std::time::Instant,
    pub last_activity: std::time::Instant,
    pub operation_count: u64,
}

pub struct PhantomSessionManager {
    sessions: Arc<RwLock<HashMap<Vec<u8>, PhantomSessionEntry>>>,
    connection_manager: Arc<PhantomConnectionManager>,
    cleanup_lock: Arc<Mutex<()>>,
}

impl PhantomSessionManager {
    pub fn new(connection_manager: Arc<PhantomConnectionManager>) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            connection_manager,
            cleanup_lock: Arc::new(Mutex::new(())),
        }
    }

    pub async fn register_session(
        &self,
        session_id: Vec<u8>,
        session: Arc<PhantomSession>,
        addr: SocketAddr,
    ) {
        let entry = PhantomSessionEntry {
            session: session.clone(),
            addr,
            created_at: std::time::Instant::now(),
            last_activity: std::time::Instant::now(),
            operation_count: 0,
        };

        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id.clone(), entry);
        }

        info!(
            "👻 Phantom session registered: {} from {}",
            hex::encode(session_id),
            addr
        );
    }

    pub async fn update_activity(&self, session_id: &[u8]) {
        let mut sessions = self.sessions.write().await;
        if let Some(entry) = sessions.get_mut(session_id) {
            entry.last_activity = std::time::Instant::now();
            entry.operation_count += 1;
        }
    }

    pub async fn get_session(&self, session_id: &[u8]) -> Option<Arc<PhantomSession>> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).map(|entry| entry.session.clone())
    }

    pub async fn session_exists(&self, session_id: &[u8]) -> bool {
        let sessions = self.sessions.read().await;
        sessions.contains_key(session_id)
    }

    pub async fn on_heartbeat_received(&self, session_id: &[u8]) -> bool {
        self.update_activity(session_id).await;
        true
    }

    pub async fn force_remove_session(&self, session_id: &[u8]) {
        let _guard = self.cleanup_lock.lock().await;

        let session_id_str = hex::encode(session_id);

        self.connection_manager.force_disconnect(session_id).await;

        {
            let mut sessions = self.sessions.write().await;
            sessions.remove(session_id);
        }

        info!("👻 Phantom session fully removed: {}", session_id_str);
    }

    pub async fn unregister_session(&self, session_id: &[u8]) {
        self.force_remove_session(session_id).await;
    }

    pub async fn is_connection_alive(&self, session_id: &[u8]) -> bool {
        let session_exists = self.session_exists(session_id).await;

        if !session_exists {
            return false;
        }

        let sessions = self.sessions.read().await;
        if let Some(entry) = sessions.get(session_id) {
            // Проверяем таймаут неактивности (60 секунд)
            let inactive_time = std::time::Instant::now().duration_since(entry.last_activity);
            if inactive_time > std::time::Duration::from_secs(60) {
                warn!("👻 Session {} inactive for {:?}", hex::encode(session_id), inactive_time);
                return false;
            }

            // Проверяем валидность сессии
            return entry.session.is_valid();
        }

        false
    }

    pub async fn get_active_sessions(&self) -> Vec<Arc<PhantomSession>> {
        let sessions = self.sessions.read().await;
        sessions
            .values()
            .filter(|entry| entry.session.is_valid())
            .map(|entry| entry.session.clone())
            .collect()
    }

    pub async fn cleanup_expired_sessions(&self, max_age_seconds: u64) -> usize {
        let now = std::time::Instant::now();
        let max_age = std::time::Duration::from_secs(max_age_seconds);

        let mut expired_ids = Vec::new();

        {
            let sessions = self.sessions.read().await;
            for (session_id, entry) in sessions.iter() {
                if now.duration_since(entry.created_at) > max_age {
                    expired_ids.push(session_id.clone());
                }
            }
        }

        let count = expired_ids.len();
        for session_id in expired_ids {
            self.force_remove_session(&session_id).await;
        }

        if count > 0 {
            info!("👻 Cleaned up {} expired phantom sessions", count);
        }

        count
    }

    pub async fn get_session_stats(&self, session_id: &[u8]) -> Option<SessionStats> {
        let sessions = self.sessions.read().await;
        sessions.get(session_id).map(|entry| SessionStats {
            session_id: hex::encode(session_id),
            addr: entry.addr,
            created_at: entry.created_at,
            last_activity: entry.last_activity,
            operation_count: entry.operation_count,
            is_valid: entry.session.is_valid(),
        })
    }
}

pub struct SessionStats {
    pub session_id: String,
    pub addr: SocketAddr,
    pub created_at: std::time::Instant,
    pub last_activity: std::time::Instant,
    pub operation_count: u64,
    pub is_valid: bool,
}

impl Default for PhantomSessionManager {
    fn default() -> Self {
        let connection_manager = Arc::new(PhantomConnectionManager::new());
        Self::new(connection_manager)
    }
}