use tracing::info;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::io::AsyncWriteExt; // Убрали AsyncReadExt, т.к. не используется

use crate::core::protocol::phantom_crypto::handshake::{perform_phantom_handshake, HandshakeRole};
use crate::core::protocol::server::session_manager_phantom::PhantomSessionManager;
use crate::core::protocol::server::connection_manager_phantom::PhantomConnectionManager;
use crate::core::protocol::crypto::crypto_pool_phantom::PhantomCryptoPool;
use crate::config::PhantomConfig;

pub struct TestServer {
    pub addr: String,
    pub phantom_config: PhantomConfig,
    pub session_manager: Arc<PhantomSessionManager>,
    pub connection_manager: Arc<PhantomConnectionManager>,
    pub crypto_pool: Arc<PhantomCryptoPool>,
    shutdown_tx: mpsc::Sender<()>,
}

impl TestServer {
    pub async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        info!(target: "test_server", "Test server listening on {}", addr);

        let phantom_config = PhantomConfig::default();

        // Инициализируем фантомные компоненты
        let connection_manager = Arc::new(PhantomConnectionManager::new());
        let session_manager = Arc::new(PhantomSessionManager::new(connection_manager.clone()));
        let crypto_pool = Arc::new(PhantomCryptoPool::spawn(4)); // 4 потока для тестов

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);

        let _server_addr = addr.clone(); // Добавляем подчеркивание
        let server_config = phantom_config.clone();
        let server_session_manager = session_manager.clone();
        let server_connection_manager = connection_manager.clone();
        let server_crypto_pool = crypto_pool.clone();

        // Запускаем сервер в отдельной задаче
        tokio::spawn(async move {
            info!("Test server task started");

            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((stream, peer)) => {
                                info!("New connection from {}", peer);

                                // Обрабатываем соединение в отдельной задаче
                                let config = server_config.clone();
                                let session_manager = server_session_manager.clone();
                                let connection_manager = server_connection_manager.clone();
                                let crypto_pool = server_crypto_pool.clone();

                                tokio::spawn(async move {
                                    if let Err(e) = Self::handle_test_connection(
                                        stream,
                                        peer,
                                        config,
                                        session_manager,
                                        connection_manager,
                                        crypto_pool
                                    ).await {
                                        info!("Connection handler error: {}", e);
                                    }
                                });
                            }
                            Err(e) => {
                                info!("Accept error: {}", e);
                                break;
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Test server received shutdown signal");
                        break;
                    }
                }
            }

            info!("Test server task stopped");
        });

        Self {
            addr,
            phantom_config,
            session_manager,
            connection_manager,
            crypto_pool,
            shutdown_tx,
        }
    }

    async fn handle_test_connection(
        stream: TcpStream,
        peer: std::net::SocketAddr,
        _config: PhantomConfig,
        session_manager: Arc<PhantomSessionManager>,
        _connection_manager: Arc<PhantomConnectionManager>,
        _crypto_pool: Arc<PhantomCryptoPool>,
    ) -> anyhow::Result<()> {
        let mut stream = stream;

        // Выполняем фантомный handshake
        match perform_phantom_handshake(&mut stream, HandshakeRole::Server).await {
            Ok(handshake_result) => {
                let session = Arc::new(handshake_result.session);
                let session_id = session.session_id().to_vec();

                info!("Phantom handshake successful for {}, session: {}",
                    peer, hex::encode(&session_id));

                // Регистрируем сессию
                session_manager.register_session(
                    session_id.clone(),
                    session.clone(),
                    peer
                ).await;

                // Простая обработка входящих данных (эхо-сервер)
                let mut buffer = [0u8; 1024];
                loop {
                    match stream.readable().await {
                        Ok(()) => {
                            match stream.try_read(&mut buffer) {
                                Ok(0) => {
                                    info!("Connection closed by client {}", peer);
                                    break;
                                }
                                Ok(n) => {
                                    info!("Received {} bytes from {}", n, peer);

                                    // Проверяем пинг-пакет (тип 0x01)
                                    if n > 0 && buffer[0] == 0x01 {
                                        info!("Received ping packet, sending pong response");
                                        // Отправляем pong (тип 0x02)
                                        let pong_response = [0x02];
                                        if let Err(e) = stream.write_all(&pong_response).await {
                                            info!("Failed to send pong response: {}", e);
                                            break;
                                        }
                                    } else {
                                        // Эхо-ответ для других данных
                                        if let Err(e) = stream.write_all(&buffer[..n]).await {
                                            info!("Failed to send echo response: {}", e);
                                            break;
                                        }
                                    }
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    continue;
                                }
                                Err(e) => {
                                    info!("Read error from {}: {}", peer, e);
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            info!("Stream error from {}: {}", peer, e);
                            break;
                        }
                    }
                }

                // Удаляем сессию при закрытии соединения
                session_manager.unregister_session(&session_id).await;
            }
            Err(e) => {
                info!("Phantom handshake failed for {}: {:?}", peer, e);
            }
        }

        Ok(())
    }

    pub async fn stop(&self) {
        info!("Stopping test server...");
        let _ = self.shutdown_tx.send(()).await;

        // Ждем завершения
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        info!("Test server stopped");
    }

    pub async fn get_session_count(&self) -> usize {
        // Получаем активные сессии из менеджера
        let sessions = self.session_manager.get_active_sessions().await;
        sessions.len()
    }
}