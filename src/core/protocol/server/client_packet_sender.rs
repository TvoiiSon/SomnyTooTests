use std::sync::Arc;
use anyhow::Result;
use tokio::time::{Duration, sleep};
use tokio::sync::{Mutex, RwLock};
use tracing::{info, debug, error, warn};

use crate::core::protocol::server::session_manager::SessionManager;
use crate::core::protocol::server::connection_manager::ConnectionManager;
use crate::core::protocol::packets::encoder::packet_builder::PacketBuilder;
use crate::core::protocol::packets::decoder::packet_parser::PacketType;
use crate::core::protocol::crypto::handshake::handshake::{perform_handshake, HandshakeRole};
use crate::core::protocol::packets::processor::dispatcher::Dispatcher;

/// Сервис для отправки пакетов от клиента на сервер с самоподдерживающимся соединением
#[derive(Clone)]
pub struct ClientPacketSender {
    session_manager: Arc<SessionManager>,
    connection_manager: Arc<ConnectionManager>,
    dispatcher: Arc<Dispatcher>,
    server_address: Arc<RwLock<String>>,
    is_connecting: Arc<Mutex<bool>>,
    max_retries: usize,
}

impl ClientPacketSender {
    pub fn new(
        session_manager: Arc<SessionManager>,
        connection_manager: Arc<ConnectionManager>,
        dispatcher: Arc<Dispatcher>,
    ) -> Self {
        let server_address = Self::get_server_address();

        Self {
            session_manager,
            connection_manager,
            dispatcher,
            server_address: Arc::new(RwLock::new(server_address)),
            is_connecting: Arc::new(Mutex::new(false)),
            max_retries: 3,
        }
    }

    /// Основной метод отправки пакета на сервер
    pub async fn send_packet(
        &self,
        packet_type: PacketType,
        payload: Vec<u8>,
    ) -> Result<()> {
        info!("🔄 Отправка пакета типа: {:?}, размер: {} байт", packet_type, payload.len());

        // 1. Проверяем, есть ли активная сессия
        if let Some(session_keys) = self.get_active_session().await {
            // Есть активная сессия - отправляем пакет
            return self.send_with_session(&session_keys, packet_type, payload).await;
        }

        // 2. Нет активной сессии - подключаемся к серверу
        info!("📡 Нет активной сессии, подключаемся к серверу...");
        self.ensure_connection().await?;

        // 3. Ждем установления соединения и регистрации сессии
        sleep(Duration::from_millis(500)).await;

        // 4. Получаем новую сессию и отправляем
        if let Some(session_keys) = self.get_active_session().await {
            self.send_with_session(&session_keys, packet_type, payload).await
        } else {
            Err(anyhow::anyhow!("Не удалось установить соединение с сервером"))
        }
    }

    /// Гарантирует наличие активного соединения с сервером
    pub async fn ensure_connection(&self) -> Result<()> {
        // Проверяем, есть ли уже активное соединение
        if self.has_active_session().await {
            info!("✅ Уже есть активное соединение с сервером");
            return Ok(());
        }

        // Блокируем повторные попытки подключения
        {
            let mut connecting = self.is_connecting.lock().await;
            if *connecting {
                info!("🔄 Подключение уже выполняется, ожидаем...");
                // Ждем завершения текущей попытки
                while *connecting {
                    drop(connecting); // Освобождаем блокировку
                    sleep(Duration::from_millis(100)).await;
                    connecting = self.is_connecting.lock().await;
                }
                return Ok(());
            }
            *connecting = true;
        }

        info!("🔌 Выполняем подключение к серверу...");

        let result = self.connect_with_retry().await;

        // Снимаем блокировку
        *self.is_connecting.lock().await = false;

        result
    }

    /// Подключение с повторными попытками
    async fn connect_with_retry(&self) -> Result<()> {
        let server_addr = self.server_address.read().await.clone();

        for attempt in 1..=self.max_retries {
            info!("🔄 Попытка подключения {}/{} к серверу {}",
                  attempt, self.max_retries, server_addr);

            match self.attempt_connection(&server_addr).await {
                Ok(_) => {
                    info!("✅ Успешное подключение к серверу");
                    return Ok(());
                }
                Err(e) if attempt == self.max_retries => {
                    error!("❌ Не удалось подключиться после {} попыток: {}",
                           self.max_retries, e);
                    return Err(e);
                }
                Err(e) => {
                    warn!("⚠️ Ошибка подключения (попытка {}): {}", attempt, e);
                    sleep(Duration::from_secs(attempt as u64)).await;
                }
            }
        }

        Err(anyhow::anyhow!("Неизвестная ошибка при подключении"))
    }

    /// Одна попытка подключения
    async fn attempt_connection(&self, server_addr: &str) -> Result<()> {
        use tokio::net::TcpStream;

        let mut stream = TcpStream::connect(server_addr).await
            .map_err(|e| anyhow::anyhow!("Не удалось подключиться к серверу {}: {}", server_addr, e))?;

        let peer = stream.peer_addr()
            .map_err(|e| anyhow::anyhow!("Не удалось получить адрес пира: {}", e))?;

        info!("✅ Установлено TCP-соединение с {}", peer);

        // Выполняем handshake
        info!("🔄 Выполнение handshake с сервером...");
        let handshake_result = perform_handshake(&mut stream, HandshakeRole::Client).await?;
        info!("✅ Handshake успешно завершен");

        // Запускаем обработку соединения в фоновой задаче
        let session_manager_clone = Arc::clone(&self.session_manager);
        let connection_manager_clone = Arc::clone(&self.connection_manager);
        let dispatcher_clone = Arc::clone(&self.dispatcher);

        tokio::spawn(async move {
            if let Err(e) = crate::core::protocol::server::connection_manager::handle_server_connection(
                stream,
                peer,
                Arc::new(handshake_result.session_keys),
                dispatcher_clone,
                session_manager_clone,
                connection_manager_clone,
            ).await {
                error!("❌ Ошибка обработки соединения с сервером: {}", e);
            }
        });

        Ok(())
    }

    /// Отправка пакета с использованием существующей сессии
    async fn send_with_session(
        &self,
        session_keys: &crate::core::protocol::crypto::key_manager::session_keys::SessionKeys,
        packet_type: PacketType,
        payload: Vec<u8>,
    ) -> Result<()> {
        debug!("📦 Создание зашифрованного пакета для сессии: {}",
               hex::encode(&session_keys.session_id));

        // Создаем зашифрованный пакет
        let encrypted_packet = PacketBuilder::build_encrypted_packet(
            session_keys,
            Self::packet_type_to_u8(packet_type),
            &payload,
        ).await;

        info!("✅ Пакет создан, размер: {} байт, отправка...", encrypted_packet.len());

        // Отправляем пакет
        match self.connection_manager.send_packet(
            &session_keys.session_id,
            encrypted_packet,
        ).await {
            Ok(_) => {
                info!("🚀 Пакет успешно отправлен на сервер");
                Ok(())
            }
            Err(e) => {
                error!("❌ Ошибка отправки пакета: {}", e);
                // Если соединение разорвано, пробуем переподключиться
                self.recover_connection().await?;
                Err(e)
            }
        }
    }

    /// Восстановление соединения при сбое
    async fn recover_connection(&self) -> Result<()> {
        warn!("🔄 Восстановление соединения после сбоя...");

        // Очищаем нерабочие сессии
        self.cleanup_dead_sessions().await;

        // Пробуем подключиться заново
        self.ensure_connection().await
    }

    /// Очистка нерабочих сессий
    async fn cleanup_dead_sessions(&self) {
        let sessions = self.session_manager.get_active_sessions().await;

        for session_keys in sessions {
            let session_id = &session_keys.session_id;
            if !self.connection_manager.connection_exists(session_id).await {
                warn!("🧹 Очищаем нерабочую сессию: {}", hex::encode(session_id));
                self.session_manager.force_remove_session(session_id).await;
            }
        }
    }

    /// Проверяем наличие активной сессии
    async fn has_active_session(&self) -> bool {
        self.get_active_session().await.is_some()
    }

    /// Получаем активную сессию
    async fn get_active_session(&self) -> Option<Arc<crate::core::protocol::crypto::key_manager::session_keys::SessionKeys>> {
        // Получаем все сессии и находим первую активную
        let sessions = self.session_manager.get_consistent_sessions().await;
        sessions.into_iter().next()
    }

    /// Обновление адреса сервера
    pub async fn update_server_address(&self, host: &str, port: &str) {
        let new_address = format!("{}:{}", host, port);
        *self.server_address.write().await = new_address.clone();
        info!("📡 Обновлен адрес сервера: {}", new_address);
    }

    /// Получение текущего адреса сервера
    pub async fn get_current_server_address(&self) -> String {
        self.server_address.read().await.clone()
    }

    fn get_server_address() -> String {
        let server_host = std::env::var("SERVER_HOST")
            .unwrap_or_else(|_| {
                warn!("SERVER_HOST не установлен, используется 127.0.0.1");
                "192.168.0.73".to_string()
            });

        let server_port = std::env::var("SERVER_PORT")
            .unwrap_or_else(|_| {
                warn!("SERVER_PORT не установлен, используется 8000");
                "8000".to_string()
            });

        format!("{}:{}", server_host, server_port)
    }

    /// Конвертация PacketType в u8
    fn packet_type_to_u8(packet_type: PacketType) -> u8 {
        match packet_type {
            PacketType::Ping => 0x01,
            PacketType::Heartbeat => 0x10,
            PacketType::Unknown(x) => x,
        }
    }
}