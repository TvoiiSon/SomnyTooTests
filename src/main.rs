use std::sync::Arc;
use dotenv::dotenv;
use tokio::runtime::Runtime;
use tracing::{info, error};
use tracing_subscriber::{FmtSubscriber, EnvFilter};
use somnytoo_test::core::protocol::server::connection_manager::ConnectionManager;
use somnytoo_test::core::protocol::server::session_manager::SessionManager;
use somnytoo_test::core::protocol::packets::processor::dispatcher::Dispatcher;
use somnytoo_test::core::protocol::server::client_packet_sender::ClientPacketSender;
use somnytoo_test::core::protocol::packets::processor::packet_service::PacketService;
use tokio::signal;
use tokio::time::{sleep, Duration};
use somnytoo_test::core::protocol::packets::decoder::packet_parser::PacketType;

fn main() {
    dotenv().ok();

    // Инициализация logging
    init_logging();

    // Создаём tokio runtime для асинхронного кода
    let rt = Runtime::new().expect("Не удалось создать tokio runtime");

    rt.block_on(async {
        info!("🚀 Запуск приложения...");

        // Инициализация систем
        initialize_all_systems().await;
    });
}

async fn initialize_all_systems() {
    info!("🔐 Инициализация всех систем...");

    // 1. Инициализация основных менеджеров
    let connection_manager = Arc::new(ConnectionManager::new());
    let session_manager = Arc::new(SessionManager::new(Arc::clone(&connection_manager)));

    // 4. Инициализация обработчика пакетов
    let packet_service = PacketService::new();

    // 5. Инициализация диспетчера
    let dispatcher = Arc::new(Dispatcher::spawn(4, packet_service));

    // 6. Инициализация отправителя пакетов
    let packet_sender = Arc::new(ClientPacketSender::new(
        Arc::clone(&session_manager),
        Arc::clone(&connection_manager),
        Arc::clone(&dispatcher),
    ));

    // Подключаемся к серверу
    if let Err(e) = packet_sender.ensure_connection().await {
        error!("❌ Не удалось подключиться к серверу: {}", e);
        return;
    }

    info!("✅ Системы инициализированы");

    // Теперь нужно держать приложение запущенным
    keep_application_running().await;
}

async fn keep_application_running() {
    info!("📡 Приложение работает, ожидание сигналов завершения...");

    // Создаем каналы для graceful shutdown
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::broadcast::channel(1);
    let shutdown_tx_clone = shutdown_tx.clone();

    // Обработка сигналов завершения
    tokio::spawn(async move {
        let ctrl_c = signal::ctrl_c();

        tokio::select! {
            _ = ctrl_c => {
                info!("🛑 Получен сигнал Ctrl+C");
                let _ = shutdown_tx_clone.send(());
            }
        }
    });

    // Ждем сигнала завершения
    let _ = shutdown_rx.recv().await;

    info!("🛑 Начинаем graceful shutdown...");

    // Даем время на завершение
    sleep(Duration::from_secs(1)).await;

    info!("👋 Приложение завершено");
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter)
        .with_target(true)
        .with_level(true)
        .with_ansi(true)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");
}