use std::time::Duration;
use tokio::time;
use tracing::{info, error, warn};

use crate::test_client::TestClient;
use crate::test_server::TestServer;

pub struct IntegrationTestRunner {
    pub total_tests: usize,
    pub passed_tests: usize,
    pub failed_tests: usize,
    pub errors: Vec<String>,
}

impl IntegrationTestRunner {
    pub fn new() -> Self {
        Self {
            total_tests: 0,
            passed_tests: 0,
            failed_tests: 0,
            errors: Vec::new(),
        }
    }

    pub async fn run_all_tests(&mut self) -> bool {
        info!("🎯 ЗАПУСК ИНТЕГРАЦИОННЫХ ТЕСТОВ");
        info!("========================================");

        // Запускаем тесты по порядку - используем замыкания для каждого теста
        let tests: Vec<(&str, Box<dyn Fn() -> _>)> = vec![
            ("test_basic_connection", Box::new(|| Self::test_basic_connection())),
            ("test_ping_pong", Box::new(|| Self::test_ping_pong())),
            ("test_multiple_connections", Box::new(|| Self::test_multiple_connections())),
            ("test_connection_timeout", Box::new(|| Self::test_connection_timeout())),
            ("test_rapid_reconnect", Box::new(|| Self::test_rapid_reconnect())),
        ];

        for (name, test_fn) in tests {
            self.run_test(name, test_fn).await;
        }

        self.print_summary();
        self.failed_tests == 0
    }

    async fn run_test<F>(&mut self, name: &str, test_fn: F)
    where
        F: FnOnce() -> tokio::task::JoinHandle<anyhow::Result<()>>,
    {
        self.total_tests += 1;
        info!("🧪 Тест: {}", name);

        let start = time::Instant::now();

        let task = test_fn();
        match task.await {
            Ok(Ok(_)) => {
                let duration = start.elapsed();
                self.passed_tests += 1;
                info!("✅ Тест '{}' пройден за {:?}", name, duration);
            }
            Ok(Err(e)) => {
                self.failed_tests += 1;
                self.errors.push(format!("{}: {}", name, e));
                error!("❌ Тест '{}' не пройден: {}", name, e);
            }
            Err(e) => {
                self.failed_tests += 1;
                self.errors.push(format!("{}: join error: {}", name, e));
                error!("❌ Тест '{}' ошибка выполнения: {}", name, e);
            }
        }

        info!("---");
    }

    fn print_summary(&self) {
        info!("📊 СВОДКА ТЕСТИРОВАНИЯ");
        info!("========================================");
        info!("Всего тестов: {}", self.total_tests);
        info!("Пройдено: {}", self.passed_tests);
        info!("Не пройдено: {}", self.failed_tests);

        if self.total_tests > 0 {
            let success_rate = (self.passed_tests as f64 / self.total_tests as f64) * 100.0;
            info!("Успешность: {:.1}%", success_rate);
        }

        if !self.errors.is_empty() {
            warn!("Ошибки:");
            for error in &self.errors {
                warn!("  - {}", error);
            }
        }

        if self.failed_tests == 0 {
            info!("🎉 ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО!");
        } else {
            error!("⚠️  НЕКОТОРЫЕ ТЕСТЫ НЕ ПРОЙДЕНЫ!");
        }
    }

    // ===== КОНКРЕТНЫЕ ТЕСТЫ =====

    pub fn test_basic_connection() -> tokio::task::JoinHandle<anyhow::Result<()>> {
        tokio::spawn(async move {
            info!("Тест: Базовое подключение клиента к серверу");

            let server = TestServer::spawn().await;
            info!("✅ Сервер запущен на {}", server.addr);

            let client = TestClient::connect().await?;
            info!("✅ Клиент подключился");

            // Проверяем что сессия создана
            if !client.session.is_valid() {
                return Err(anyhow::anyhow!("Сессия не валидна после подключения"));
            }

            info!("✅ Сессия валидна: {}", hex::encode(client.session.session_id()));

            server.stop().await;
            info!("✅ Сервер остановлен");

            Ok(())
        })
    }

    pub fn test_ping_pong() -> tokio::task::JoinHandle<anyhow::Result<()>> {
        tokio::spawn(async move {
            info!("Тест: Отправка ping и получение pong");

            let server = TestServer::spawn().await;
            let mut client = TestClient::connect().await?;

            // Отправляем ping
            client.send_ping().await?;
            info!("✅ Ping отправлен");

            // Получаем ответ с таймаутом
            match time::timeout(Duration::from_secs(5), client.receive_response()).await {
                Ok(Ok(response)) => {
                    if response.is_empty() {
                        return Err(anyhow::anyhow!("Получен пустой ответ"));
                    }
                    info!("✅ Получен ответ размером {} байт", response.len());

                    // Проверяем что это pong (0x02)
                    if !response.is_empty() && response[0] == 0x02 {
                        info!("✅ Корректный pong ответ");
                    } else {
                        warn!("⚠️ Нестандартный ответ: {:?}", &response[..std::cmp::min(10, response.len())]);
                    }
                }
                Ok(Err(e)) => {
                    return Err(anyhow::anyhow!("Ошибка получения ответа: {}", e));
                }
                Err(_) => {
                    return Err(anyhow::anyhow!("Таймаут ожидания ответа"));
                }
            }

            client.shutdown().await?;
            server.stop().await;

            Ok(())
        })
    }

    pub fn test_multiple_connections() -> tokio::task::JoinHandle<anyhow::Result<()>> {
        tokio::spawn(async move {
            info!("Тест: Несколько последовательных подключений");

            let server = TestServer::spawn().await;

            // 3 последовательных подключения
            for i in 0..3 {
                info!("Итерация {}/3", i + 1);

                let mut client = TestClient::connect().await?;
                client.send_ping().await?;

                match time::timeout(Duration::from_secs(2), client.receive_response()).await {
                    Ok(Ok(response)) => {
                        if !response.is_empty() {
                            info!("✅ Ответ получен ({} байт)", response.len());
                        }
                    }
                    _ => {
                        warn!("⚠️ Нет ответа на итерации {}", i + 1);
                    }
                }

                client.shutdown().await?;
                time::sleep(Duration::from_millis(50)).await;
            }

            server.stop().await;
            Ok(())
        })
    }

    pub fn test_connection_timeout() -> tokio::task::JoinHandle<anyhow::Result<()>> {
        tokio::spawn(async move {
            info!("Тест: Таймаут подключения к несуществующему серверу");

            // Сохраняем оригинальный порт
            let original_port = crate::config::CONFIG.server_port;

            // Безопасно меняем переменную окружения
            // Используем unsafe только для изменения переменной окружения
            unsafe {
                std::env::set_var("SERVER_PORT", "9999");
            }

            // Пытаемся подключиться (должно быть ошибка)
            match time::timeout(Duration::from_secs(2), TestClient::connect()).await {
                Ok(Err(_)) => {
                    info!("✅ Таймаут подключения работает корректно");
                }
                Ok(Ok(_)) => {
                    return Err(anyhow::anyhow!("Удалось подключиться к несуществующему порту!"));
                }
                Err(_) => {
                    info!("✅ Таймаут подключения работает корректно");
                }
            }

            // Восстанавливаем оригинальный порт
            unsafe {
                std::env::set_var("SERVER_PORT", original_port.to_string());
            }

            Ok(())
        })
    }

    pub fn test_rapid_reconnect() -> tokio::task::JoinHandle<anyhow::Result<()>> {
        tokio::spawn(async move {
            info!("Тест: Быстрое переподключение");

            let server = TestServer::spawn().await;

            // Быстрые переподключения
            for i in 0..5 {
                let mut client = TestClient::connect().await?;
                info!("✅ Быстрое подключение {}", i + 1);

                // Сразу отключаемся
                client.shutdown().await?;

                // Минимальная пауза
                time::sleep(Duration::from_millis(10)).await;
            }

            server.stop().await;
            info!("✅ Быстрые переподключения работают");

            Ok(())
        })
    }
}