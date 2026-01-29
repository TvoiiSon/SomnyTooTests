use dotenv::dotenv;
use tracing_subscriber::{FmtSubscriber, EnvFilter};
use clap::{Parser, Subcommand};

use somnytoo_test::tests::integrations::IntegrationTestRunner;
use somnytoo_test::tests::improved_integration::ImprovedIntegrationTestRunner;

/// CLI для запуска тестов
#[derive(Parser)]
#[command(name = "SomnyTooTests")]
#[command(about = "Клиент для тестирования SomnyToo сервера", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Запустить все интеграционные тесты
    Test,

    /// Запустить улучшенные интеграционные тесты
    TestImproved,

    /// Запустить все тесты (обычные + улучшенные)
    TestAll,

    /// Запустить определенный тест
    Run {
        /// Название теста
        test_name: String,
    },

    /// Запустить нагрузочный тест
    LoadTest {
        /// Количество клиентов
        #[arg(default_value_t = 10)]
        clients: usize,

        /// Максимум параллельных подключений
        #[arg(default_value_t = 3)]
        concurrent: usize,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();

    // Инициализация логирования
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter)
        .with_target(true)
        .with_level(true)
        .with_ansi(true)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("Не удалось установить логгер");

    let cli = Cli::parse();

    match cli.command {
        Commands::Test => {
            run_legacy_tests().await?;
        }
        Commands::TestImproved => {
            run_improved_tests().await?;
        }
        Commands::TestAll => {
            run_all_test_suites().await?;
        }
        Commands::Run { test_name } => {
            run_single_test(&test_name).await?;
        }
        Commands::LoadTest { clients, concurrent } => {
            run_load_test(clients, concurrent).await?;
        }
    }

    Ok(())
}

async fn run_legacy_tests() -> anyhow::Result<()> {
    println!("========================================");
    println!("   БАЗОВОЕ ИНТЕГРАЦИОННОЕ ТЕСТИРОВАНИЕ");
    println!("========================================\n");

    let mut runner = IntegrationTestRunner::new();
    let success = runner.run_all_tests().await;

    if success {
        println!("\n🎉 ВСЕ БАЗОВЫЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО!");
        Ok(())
    } else {
        println!("\n⚠️  НЕКОТОРЫЕ БАЗОВЫЕ ТЕСТЫ НЕ ПРОЙДЕНЫ!");
        Err(anyhow::anyhow!("Базовое тестирование завершилось с ошибками"))
    }
}

async fn run_improved_tests() -> anyhow::Result<()> {
    println!("========================================");
    println!("   УЛУЧШЕННОЕ ИНТЕГРАЦИОННОЕ ТЕСТИРОВАНИЕ");
    println!("========================================\n");

    let mut runner = ImprovedIntegrationTestRunner::new();
    let success = runner.run_all_tests().await;

    if success {
        println!("\n🎉 ВСЕ УЛУЧШЕННЫЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО!");
        Ok(())
    } else {
        println!("\n⚠️  НЕКОТОРЫЕ УЛУЧШЕННЫЕ ТЕСТЫ НЕ ПРОЙДЕНЫ!");
        Err(anyhow::anyhow!("Улучшенное тестирование завершилось с ошибками"))
    }
}

async fn run_all_test_suites() -> anyhow::Result<()> {
    println!("========================================");
    println!("   ПОЛНОЕ ТЕСТИРОВАНИЕ СИСТЕМЫ");
    println!("========================================\n");

    let mut all_success = true;

    // Запускаем базовые тесты
    println!("1. Запуск базовых тестов...");
    match run_legacy_tests().await {
        Ok(_) => println!("✅ Базовые тесты пройдены\n"),
        Err(e) => {
            println!("❌ Ошибка базовых тестов: {}", e);
            all_success = false;
        }
    }

    // Запускаем улучшенные тесты
    println!("2. Запуск улучшенных тестов...");
    match run_improved_tests().await {
        Ok(_) => println!("✅ Улучшенные тесты пройдены\n"),
        Err(e) => {
            println!("❌ Ошибка улучшенных тестов: {}", e);
            all_success = false;
        }
    }

    if all_success {
        println!("========================================");
        println!("🎉 ВСЕ ТЕСТЫ СИСТЕМЫ ПРОЙДЕНЫ УСПЕШНО!");
        println!("========================================");
        Ok(())
    } else {
        println!("========================================");
        println!("⚠️  НЕКОТОРЫЕ ТЕСТЫ СИСТЕМЫ НЕ ПРОЙДЕНЫ!");
        println!("========================================");
        Err(anyhow::anyhow!("Полное тестирование завершилось с ошибками"))
    }
}

async fn run_single_test(test_name: &str) -> anyhow::Result<()> {
    println!("Запуск теста: {}", test_name);

    // Сначала проверяем базовые тесты
    match test_name {
        // Базовые тесты
        "basic_connection" => {
            let task = IntegrationTestRunner::test_basic_connection();
            match task.await {
                Ok(Ok(_)) => println!("✅ Тест пройден успешно!"),
                Ok(Err(e)) => {
                    println!("❌ Ошибка теста: {}", e);
                    return Err(e);
                }
                Err(e) => {
                    println!("❌ Ошибка выполнения: {}", e);
                    return Err(anyhow::anyhow!("Ошибка выполнения: {}", e));
                }
            }
        }
        "ping_pong" => {
            let task = IntegrationTestRunner::test_ping_pong();
            match task.await {
                Ok(Ok(_)) => println!("✅ Тест пройден успешно!"),
                Ok(Err(e)) => {
                    println!("❌ Ошибка теста: {}", e);
                    return Err(e);
                }
                Err(e) => {
                    println!("❌ Ошибка выполнения: {}", e);
                    return Err(anyhow::anyhow!("Ошибка выполнения: {}", e));
                }
            }
        }
        "multiple_connections" => {
            let task = IntegrationTestRunner::test_multiple_connections();
            match task.await {
                Ok(Ok(_)) => println!("✅ Тест пройден успешно!"),
                Ok(Err(e)) => {
                    println!("❌ Ошибка теста: {}", e);
                    return Err(e);
                }
                Err(e) => {
                    println!("❌ Ошибка выполнения: {}", e);
                    return Err(anyhow::anyhow!("Ошибка выполнения: {}", e));
                }
            }
        }
        "connection_timeout" => {
            let task = IntegrationTestRunner::test_connection_timeout();
            match task.await {
                Ok(Ok(_)) => println!("✅ Тест пройден успешно!"),
                Ok(Err(e)) => {
                    println!("❌ Ошибка теста: {}", e);
                    return Err(e);
                }
                Err(e) => {
                    println!("❌ Ошибка выполнения: {}", e);
                    return Err(anyhow::anyhow!("Ошибка выполнения: {}", e));
                }
            }
        }
        "rapid_reconnect" => {
            let task = IntegrationTestRunner::test_rapid_reconnect();
            match task.await {
                Ok(Ok(_)) => println!("✅ Тест пройден успешно!"),
                Ok(Err(e)) => {
                    println!("❌ Ошибка теста: {}", e);
                    return Err(e);
                }
                Err(e) => {
                    println!("❌ Ошибка выполнения: {}", e);
                    return Err(anyhow::anyhow!("Ошибка выполнения: {}", e));
                }
            }
        }
        // Улучшенные тесты
        "improved_basic_connection" => {
            let task = ImprovedIntegrationTestRunner::test_improved_basic_connection();
            match task.await {
                Ok(Ok(_)) => println!("✅ Тест пройден успешно!"),
                Ok(Err(e)) => {
                    println!("❌ Ошибка теста: {}", e);
                    return Err(e);
                }
                Err(e) => {
                    println!("❌ Ошибка выполнения: {}", e);
                    return Err(anyhow::anyhow!("Ошибка выполнения: {}", e));
                }
            }
        }
        "encrypted_ping_pong" => {
            let task = ImprovedIntegrationTestRunner::test_encrypted_ping_pong();
            match task.await {
                Ok(Ok(_)) => println!("✅ Тест пройден успешно!"),
                Ok(Err(e)) => {
                    println!("❌ Ошибка теста: {}", e);
                    return Err(e);
                }
                Err(e) => {
                    println!("❌ Ошибка выполнения: {}", e);
                    return Err(anyhow::anyhow!("Ошибка выполнения: {}", e));
                }
            }
        }
        "session_persistence" => {
            let task = ImprovedIntegrationTestRunner::test_session_persistence();
            match task.await {
                Ok(Ok(_)) => println!("✅ Тест пройден успешно!"),
                Ok(Err(e)) => {
                    println!("❌ Ошибка теста: {}", e);
                    return Err(e);
                }
                Err(e) => {
                    println!("❌ Ошибка выполнения: {}", e);
                    return Err(anyhow::anyhow!("Ошибка выполнения: {}", e));
                }
            }
        }
        "connection_timeout_fixed" => {
            let task = ImprovedIntegrationTestRunner::test_connection_timeout_fixed();
            match task.await {
                Ok(Ok(_)) => println!("✅ Тест пройден успешно!"),
                Ok(Err(e)) => {
                    println!("❌ Ошибка теста: {}", e);
                    return Err(e);
                }
                Err(e) => {
                    println!("❌ Ошибка выполнения: {}", e);
                    return Err(anyhow::anyhow!("Ошибка выполнения: {}", e));
                }
            }
        }
        _ => {
            println!("❌ Неизвестный тест: {}", test_name);
            println!("Доступные тесты:");
            println!("\nБазовые тесты:");
            println!("  basic_connection     - Базовое подключение");
            println!("  ping_pong           - Ping-Pong тест");
            println!("  multiple_connections - Множественные подключения");
            println!("  connection_timeout  - Таймаут подключения");
            println!("  rapid_reconnect     - Быстрое переподключение");
            println!("\nУлучшенные тесты:");
            println!("  improved_basic_connection - Улучшенное базовое подключение");
            println!("  encrypted_ping_pong      - Зашифрованный ping-pong");
            println!("  session_persistence      - Сохранение состояния сессии");
            println!("  connection_timeout_fixed - Таймаут подключения (исправленный)");
            return Ok(());
        }
    }

    println!("✅ Тест '{}' пройден успешно!", test_name);
    Ok(())
}

async fn run_load_test(clients: usize, concurrent: usize) -> anyhow::Result<()> {
    use tokio::sync::Semaphore;
    use std::sync::Arc;
    use std::time::Instant;

    println!("========================================");
    println!("   НАГРУЗОЧНОЕ ТЕСТИРОВАНИЕ");
    println!("========================================\n");
    println!("Клиентов: {}", clients);
    println!("Параллельно: {}", concurrent);
    println!();

    let server = somnytoo_test::test_server::TestServer::spawn().await;
    println!("✅ Сервер запущен");

    let semaphore = Arc::new(Semaphore::new(concurrent));
    let mut tasks = Vec::new();
    let start_time = Instant::now();

    println!("🔄 Запуск клиентов...");

    for client_id in 0..clients {
        let semaphore = Arc::clone(&semaphore);

        tasks.push(tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();

            match somnytoo_test::test_client::TestClient::connect().await {
                Ok(mut client) => {
                    let _ = client.send_ping().await;
                    let _ = client.receive_response().await;
                    let _ = client.shutdown().await;
                    Some(client_id)
                }
                Err(_) => None,
            }
        }));

        // Небольшая задержка между запуском клиентов
        if client_id < clients - 1 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    // Ждем завершения всех задач
    let mut successful = 0;
    let mut failed = 0;

    for task in tasks {
        match task.await {
            Ok(Some(_)) => successful += 1,
            Ok(None) => failed += 1,
            Err(_) => failed += 1,
        }
    }

    let total_time = start_time.elapsed();

    println!("\n📊 РЕЗУЛЬТАТЫ НАГРУЗОЧНОГО ТЕСТА:");
    println!("  Всего клиентов: {}", clients);
    println!("  Успешно: {}", successful);
    println!("  Неудачно: {}", failed);
    println!("  Общее время: {:?}", total_time);

    if successful > 0 {
        let avg_time = total_time / successful as u32;
        println!("  Среднее время на клиента: {:?}", avg_time);
        println!("  Клиентов в секунду: {:.1}",
                 successful as f64 / total_time.as_secs_f64());
    }

    let success_rate = successful as f64 / clients as f64 * 100.0;
    println!("  Успешность: {:.1}%", success_rate);

    // Останавливаем сервер
    server.stop().await;
    println!("\n✅ Сервер остановлен");

    if success_rate >= 90.0 {
        println!("\n🎉 Нагрузочный тест пройден успешно!");
        Ok(())
    } else {
        println!("\n⚠️  Нагрузочный тест не пройден (успешность < 90%)");
        Err(anyhow::anyhow!("Низкая успешность нагрузочного теста"))
    }
}