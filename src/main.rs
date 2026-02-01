use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use anyhow::Result;
use tracing_subscriber::{FmtSubscriber, EnvFilter};
use tracing::{info, error, warn};

use somnytoo_test::config::CLIENT_CONFIG;
use somnytoo_test::core::protocol::phantom_crypto::core::handshake::{perform_phantom_handshake, HandshakeRole};
use somnytoo_test::core::protocol::phantom_crypto::packet::PhantomPacketProcessor;

// Импортируем batch компоненты
use somnytoo_test::core::protocol::phantom_crypto::batch::{
    io::writer::batch_writer::{BatchWriter, BatchWriterConfig},
};

use somnytoo_test::tests::ping_sender::{start_ping_sender_task, test_packet_creation};

#[tokio::main]
async fn main() -> Result<()> {
    // Настройка логирования
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter)
        .with_target(true)
        .with_level(true)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    info!("🚀 Starting Phantom Protocol Client with Batch System...");

    info!("📝 Configuration:");
    info!("  - Server: {}", CLIENT_CONFIG.server_addr());
    info!("  - Timeout: {}ms", CLIENT_CONFIG.connect_timeout_ms);

    // Запуск клиента с batch системой
    run_client_with_batch().await
}

async fn run_client_with_batch() -> Result<()> {
    let addr = CLIENT_CONFIG.server_addr();
    let server_addr_parsed = addr.parse()?;

    info!("🔗 Connecting to server at {}...", addr);

    // Подключение к серверу
    let stream = tokio::time::timeout(
        Duration::from_millis(CLIENT_CONFIG.connect_timeout_ms),
        TcpStream::connect(&addr)
    ).await??;

    info!("✅ Connected to server");

    // Для handshake нужен &mut, создаем копию потока через into_split
    info!("🤝 Performing phantom handshake...");

    // Делаем handshake НА ОРИГИНАЛЬНОМ потоке
    let mut stream_for_handshake = stream;
    let handshake_result = perform_phantom_handshake(
        &mut stream_for_handshake,
        HandshakeRole::Client
    ).await?;

    // Ждем 100ms чтобы сервер успел запустить BatchReader
    info!("⏳ Waiting for server BatchReader to initialize...");
    tokio::time::sleep(Duration::from_millis(100)).await;

    info!("🚀 Starting to send packets...");

    let session = Arc::new(handshake_result.session);
    let session_id = session.session_id();
    let session_id_bytes = session_id.to_vec();

    info!("✅ Handshake completed! Session ID: {}", hex::encode(session_id));
    info!("🕐 Handshake time: {:?}", handshake_result.handshake_time);

    // ТЕСТ: Проверяем создание пакета
    info!("🧪 Testing packet creation...");
    if let Err(e) = test_packet_creation(&session) {
        error!("❌ Packet creation test failed: {}", e);
        return Err(e);
    }

    // Теперь у нас есть stream_for_handshake, который мы будем использовать для всего
    let stream = stream_for_handshake;

    // Инициализируем batch систему
    info!("🚀 Initializing client batch system...");

    // Создаем BatchWriter
    let writer_config = BatchWriterConfig {
        batch_size: 1,
        max_batch_size: 64,
        flush_interval_ms: 100,
        max_buffer_size: 1024 * 1024,
        write_timeout_ms: 5000,
        retry_count: 3,
        retry_delay_ms: 100,
    };

    let (batch_writer, mut writer_events_rx) = BatchWriter::new(writer_config);
    let batch_writer = Arc::new(batch_writer);

    // Регистрируем соединение в BatchWriter
    info!("📤 Registering connection with BatchWriter...");

    // Создаем обертку для потока, которая реализует AsyncWrite
    struct TcpStreamWriter(tokio::net::tcp::OwnedWriteHalf);

    impl tokio::io::AsyncWrite for TcpStreamWriter {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    // Разделяем поток на чтение и запись
    let (stream_for_reader, stream_for_writer) = stream.into_split();

    match batch_writer.register_connection(
        server_addr_parsed,
        session_id_bytes.clone(),
        Box::new(TcpStreamWriter(stream_for_writer)),
    ).await {
        Ok(_) => info!("✅ Connection registered with BatchWriter"),
        Err(e) => {
            error!("❌ Failed to register connection with BatchWriter: {}", e);
            return Err(e.into());
        }
    }

    // Запускаем задачу для обработки событий BatchWriter
    let batch_writer_events_task = tokio::spawn(async move {
        while let Some(event) = writer_events_rx.recv().await {
            match event {
                somnytoo_test::core::protocol::phantom_crypto::batch::io::writer::batch_writer::BatchWriterEvent::WriteCompleted {
                    destination_addr,
                    batch_id,
                    bytes_written,
                    write_time,
                } => {
                    info!("📤 Batch #{} sent to {}: {} bytes in {:?}",
                          batch_id, destination_addr, bytes_written, write_time);
                }
                _ => {} // Игнорируем другие события
            }
        }
    });

    // Запускаем ДВЕ задачи параллельно:
    // 1. Чтение ответов от сервера
    // 2. Отправка пакетов через PingSender

    let batch_writer_clone = Arc::clone(&batch_writer);
    let session_clone = Arc::clone(&session);

    // Задача для отправки PING пакетов (используем PingSender)
    let send_task = tokio::spawn(async move {
        info!("🎯 Starting ping sender task...");

        if let Err(e) = start_ping_sender_task(
            batch_writer_clone,
            session_clone,
            server_addr_parsed,
            3, // количество пакетов
            2000, // интервал 2 секунды
        ).await {
            error!("❌ Ping sender task failed: {}", e);
        }
    });

    // Задача для чтения ответов
    let read_task = tokio::spawn(async move {
        if let Err(e) = handle_server_responses(stream_for_reader, session).await {
            warn!("📭 Server response handler error: {}", e);
        }
    });

    // Ждем завершения задач отправки и чтения
    let (send_result, read_result, _) = tokio::join!(send_task, read_task, batch_writer_events_task);

    if let Err(e) = send_result {
        error!("❌ Send task failed: {}", e);
    }

    if let Err(e) = read_result {
        error!("❌ Read task failed: {}", e);
    }

    info!("👋 Client shutdown complete");
    Ok(())
}

async fn handle_server_responses(
    mut stream: tokio::net::tcp::OwnedReadHalf,
    session: Arc<somnytoo_test::core::protocol::phantom_crypto::core::keys::PhantomSession>,
) -> Result<()> {
    info!("👂 Listening for server responses...");

    let packet_processor = PhantomPacketProcessor::new();

    loop {
        // Читаем фреймы от сервера с таймаутом
        match tokio::time::timeout(
            Duration::from_secs(30),
            somnytoo_test::core::protocol::packets::frame_reader::read_frame(&mut stream)
        ).await {
            Ok(Ok(frame_data)) => {
                if frame_data.is_empty() {
                    info!("📭 Server closed connection (empty frame)");
                    break;
                }

                // Обрабатываем пакет
                match packet_processor.process_incoming_vec(&frame_data, &session) {
                    Ok((packet_type, payload)) => {
                        match packet_type {
                            0x01 => info!("🏓 PONG received from server: {}", String::from_utf8_lossy(&payload)),
                            _ => info!("📥 Packet 0x{:02X} received from server: {} bytes",
                                      packet_type, payload.len()),
                        }
                    }
                    Err(e) => {
                        warn!("❌ Failed to process server packet: {}", e);
                    }
                }
            }
            Ok(Err(e)) => {
                info!("📭 Connection error: {}", e);
                break;
            }
            Err(_) => {
                warn!("⏰ Read timeout after 30 seconds");
                break;
            }
        }
    }

    info!("📭 Read task completed");
    Ok(())
}