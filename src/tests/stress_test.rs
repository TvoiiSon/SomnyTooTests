use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, RwLock, mpsc};
use anyhow::Result;
use tracing::{info, error, warn, debug};

use crate::core::protocol::phantom_crypto::packet::PhantomPacketProcessor;
use crate::tests::test_utils::{establish_test_connection, send_frame, read_frame, close_connection};

/// Конфигурация стресс-теста
#[derive(Debug, Clone)]
pub struct StressTestConfig {
    pub total_clients: usize,
    pub max_concurrent: usize,
    pub packets_per_client: usize,
    pub packet_delay_ms: u64,
    pub test_duration_secs: u64,
    pub enable_random_delays: bool,
    pub payload_sizes: Vec<usize>,
}

impl Default for StressTestConfig {
    fn default() -> Self {
        Self {
            total_clients: 10,
            max_concurrent: 5,
            packets_per_client: 3,
            packet_delay_ms: 100,
            test_duration_secs: 30,
            enable_random_delays: false,
            payload_sizes: vec![16, 64, 256],
        }
    }
}

/// Результаты стресс-теста
#[derive(Debug, Clone)]
pub struct StressTestResult {
    pub total_connections: usize,
    pub successful_connections: usize,
    pub total_packets_sent: usize,
    pub total_packets_received: usize,
    pub total_bytes_sent: usize,
    pub total_bytes_received: usize,
    pub total_duration: Duration,
    pub clients_per_second: f64,
    pub packets_per_second: f64,
    pub success_rate: f64,
    pub throughput_mbps: f64,
    pub errors: Vec<String>,
}

impl StressTestResult {
    pub fn new() -> Self {
        Self {
            total_connections: 0,
            successful_connections: 0,
            total_packets_sent: 0,
            total_packets_received: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
            total_duration: Duration::default(),
            clients_per_second: 0.0,
            packets_per_second: 0.0,
            success_rate: 0.0,
            throughput_mbps: 0.0,
            errors: Vec::new(),
        }
    }
}

/// Запуск стресс-теста с заданной конфигурацией
pub async fn run_stress_test(config: StressTestConfig) -> Result<StressTestResult> {
    info!("🧪 Starting stress test...");
    info!("📊 Configuration: {:?}", config);

    let semaphore = Arc::new(Semaphore::new(config.max_concurrent));
    let test_start = Instant::now();

    // Создаем канал для сбора результатов от клиентов
    let (tx, mut rx) = mpsc::channel::<ClientResult>(config.total_clients);

    // Создаем задачи для каждого клиента - ПАРАЛЛЕЛЬНО!
    let mut tasks = Vec::new();

    for client_id in 0..config.total_clients {
        let config = config.clone();
        let semaphore = Arc::clone(&semaphore);
        let tx = tx.clone();

        let task = tokio::spawn(async move {
            // Ждем разрешения на параллельное выполнение
            let _permit = match semaphore.acquire().await {
                Ok(permit) => permit,
                Err(_) => {
                    warn!("Client {}: Semaphore error", client_id);
                    return;
                }
            };

            // Запускаем клиента
            let client_result = run_single_client(client_id, config).await;

            // Отправляем результат
            let _ = tx.send(client_result).await;
        });

        tasks.push(task);

        // Небольшая задержка между созданием задач для равномерного распределения
        if client_id % 100 == 0 && client_id > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    // Не забываем закрыть отправителя
    drop(tx);

    // Собираем результаты от всех клиентов
    let mut client_results = Vec::new();
    while let Some(client_result) = rx.recv().await {
        client_results.push(client_result);
    }

    // Ждем завершения всех задач (на всякий случай)
    for task in tasks {
        let _ = task.await;
    }

    let total_duration = test_start.elapsed();

    // Агрегируем результаты
    let mut final_result = StressTestResult::new();
    final_result.total_duration = total_duration;

    for client_result in client_results {
        final_result.total_connections += 1;
        final_result.successful_connections += client_result.successful_connections;
        final_result.total_packets_sent += client_result.packets_sent;
        final_result.total_packets_received += client_result.packets_received;
        final_result.total_bytes_sent += client_result.bytes_sent;
        final_result.total_bytes_received += client_result.bytes_received;
        final_result.errors.extend(client_result.errors);
    }

    // Рассчитываем метрики
    if final_result.total_connections > 0 {
        final_result.success_rate =
            (final_result.successful_connections as f64 / final_result.total_connections as f64) * 100.0;
    }

    // Рассчитываем производительность
    let duration_secs = total_duration.as_secs_f64();
    if duration_secs > 0.0 {
        final_result.clients_per_second = final_result.total_connections as f64 / duration_secs;
        final_result.packets_per_second = final_result.total_packets_sent as f64 / duration_secs;

        // Рассчитываем throughput
        let total_bytes = (final_result.total_bytes_sent + final_result.total_bytes_received) as f64;
        final_result.throughput_mbps = (total_bytes * 8.0) / (duration_secs * 1_000_000.0);
    }

    // Выводим результаты
    print_stress_test_results(&final_result);

    Ok(final_result)
}

/// Результат работы одного клиента
#[derive(Debug)]
struct ClientResult {
    client_id: usize,
    successful_connections: usize,
    packets_sent: usize,
    packets_received: usize,
    bytes_sent: usize,
    bytes_received: usize,
    errors: Vec<String>,
}

/// Запуск одного клиента в стресс-тесте
async fn run_single_client(
    client_id: usize,
    config: StressTestConfig,
) -> ClientResult {
    let mut result = ClientResult {
        client_id,
        successful_connections: 0,
        packets_sent: 0,
        packets_received: 0,
        bytes_sent: 0,
        bytes_received: 0,
        errors: Vec::new(),
    };

    // Устанавливаем соединение
    let connection_start = Instant::now();
    let connection_result = establish_test_connection().await;
    let connection_time = connection_start.elapsed();

    match connection_result {
        Ok((session, mut read_stream, mut write_stream)) => {
            result.successful_connections = 1;

            if client_id % 100 == 0 {
                debug!("Client {}: Connected in {:?}", client_id, connection_time);
            }

            let packet_processor = PhantomPacketProcessor::new();

            // Отправляем все пакеты
            for packet_num in 0..config.packets_per_client {
                let payload_size = config.payload_sizes[packet_num % config.payload_sizes.len()];
                let payload = generate_payload(payload_size, client_id, packet_num);

                match packet_processor.create_outgoing_vec(&session, 0x01, &payload) {
                    Ok(ping_packet) => {
                        result.bytes_sent += ping_packet.len();

                        // Отправляем пакет
                        match send_frame(&mut write_stream, &ping_packet).await {
                            Ok(_) => {
                                result.packets_sent += 1;

                                // Пытаемся получить ответ (не обязательно ждать)
                                let read_timeout = Duration::from_millis(500);
                                match tokio::time::timeout(read_timeout, read_frame(&mut read_stream)).await {
                                    Ok(Ok(frame_data)) if !frame_data.is_empty() => {
                                        result.bytes_received += frame_data.len();

                                        match packet_processor.process_incoming_vec(&frame_data, &session) {
                                            Ok((packet_type, _)) if packet_type == 0x01 => {
                                                result.packets_received += 1;
                                            }
                                            Err(e) => {
                                                result.errors.push(format!(
                                                    "Client {} packet {} process error: {}",
                                                    client_id, packet_num, e
                                                ));
                                            }
                                            _ => {
                                                // Не PONG ответ, но не ошибка
                                            }
                                        }
                                    }
                                    Ok(Ok(_)) => {
                                        // Пустой ответ
                                        result.errors.push(format!(
                                            "Client {} packet {}: Empty response",
                                            client_id, packet_num
                                        ));
                                    }
                                    Ok(Err(e)) => {
                                        result.errors.push(format!(
                                            "Client {} packet {} read error: {}",
                                            client_id, packet_num, e
                                        ));
                                    }
                                    Err(_) => {
                                        // Таймаут - нормально для стресс-теста
                                    }
                                }
                            }
                            Err(e) => {
                                // Ошибка отправки - соединение разорвано
                                result.errors.push(format!(
                                    "Client {} packet {} send error: {}",
                                    client_id, packet_num, e
                                ));
                                break; // Выходим из цикла
                            }
                        }
                    }
                    Err(e) => {
                        result.errors.push(format!(
                            "Client {} packet {} create error: {}",
                            client_id, packet_num, e
                        ));
                    }
                }

                // Задержка между пакетами (кроме последнего)
                if packet_num < config.packets_per_client - 1 {
                    let delay = if config.enable_random_delays {
                        // Простая генерация задержки без rand
                        let timestamp = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_micros();

                        ((timestamp % (config.packet_delay_ms as u128 * 1000)) / 1000) as u64 + 10
                    } else {
                        config.packet_delay_ms
                    };

                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
            }

            // Закрываем соединение
            close_connection(&mut write_stream).await;

            if client_id % 100 == 0 {
                debug!("Client {}: Finished, sent {} packets", client_id, result.packets_sent);
            }
        }
        Err(e) => {
            result.errors.push(format!(
                "Client {} connection error: {}",
                client_id, e
            ));

            if client_id % 100 == 0 {
                warn!("Client {}: Failed to connect", client_id);
            }
        }
    }

    result
}

/// Генерирует тестовые данные для пакета
fn generate_payload(size: usize, client_id: usize, packet_num: usize) -> Vec<u8> {
    let timestamp = chrono::Local::now().timestamp_millis();
    let mut payload = format!("PING_{}_{}_{}", client_id, packet_num, timestamp).into_bytes();

    // Дополняем до нужного размера
    if payload.len() < size {
        let padding = "X".repeat(size - payload.len());
        payload.extend(padding.as_bytes());
    } else {
        payload.truncate(size);
    }

    payload
}

/// Печатает результаты теста
fn print_stress_test_results(result: &StressTestResult) {
    info!("\n");
    info!("📊 ================= STRESS TEST RESULTS ===================");
    info!("📈 Total connections attempted: {}", result.total_connections);
    info!("✅ Successful connections: {}", result.successful_connections);
    info!("🚀 Clients per second: {:.2}", result.clients_per_second);
    info!("📤 Packets sent: {}", result.total_packets_sent);
    info!("📥 Packets received: {}", result.total_packets_received);
    info!("⚡ Packets per second: {:.2}", result.packets_per_second);
    info!("📦 Bytes sent: {}", result.total_bytes_sent);
    info!("📦 Bytes received: {}", result.total_bytes_received);
    info!("⏱️  Total duration: {:?}", result.total_duration);
    info!("📈 Success rate: {:.2}%", result.success_rate);
    info!("🚀 Throughput: {:.2} Mbps", result.throughput_mbps);

    if !result.errors.is_empty() {
        info!("⚠️  Errors: {}", result.errors.len());
        let unique_errors = get_unique_errors(&result.errors, 5);
        for (i, error) in unique_errors.iter().enumerate() {
            info!("   {}. {} ({} occurrences)", i + 1, error.0, error.1);
        }
        if result.errors.len() > 5 {
            info!("   ... and {} more errors", result.errors.len() - 5);
        }
    }

    info!("==========================================================");
    info!("\n");
}

/// Группирует ошибки по типу
fn get_unique_errors(errors: &[String], limit: usize) -> Vec<(String, usize)> {
    use std::collections::HashMap;

    let mut error_counts: HashMap<String, usize> = HashMap::new();

    for error in errors {
        // Извлекаем основную часть ошибки (до первых 100 символов)
        let key = if error.len() > 100 {
            format!("{}...", &error[..100])
        } else {
            error.clone()
        };

        *error_counts.entry(key).or_insert(0) += 1;
    }

    let mut sorted_errors: Vec<(String, usize)> = error_counts.into_iter().collect();
    sorted_errors.sort_by(|a, b| b.1.cmp(&a.1)); // Сортируем по частоте

    sorted_errors.into_iter().take(limit).collect()
}

/// Быстрый стресс-тест с параметрами по умолчанию
pub async fn stress_test_quick() -> Result<()> {
    info!("⚡ Running quick stress test...");

    let config = StressTestConfig {
        total_clients: 100,
        max_concurrent: 20,
        packets_per_client: 10,
        packet_delay_ms: 50,
        test_duration_secs: 15,
        enable_random_delays: true,
        payload_sizes: vec![16, 32, 64],
    };

    let result = run_stress_test(config).await?;

    if result.success_rate >= 90.0 && result.clients_per_second >= 10.0 {
        info!("✅ Quick stress test PASSED");
    } else {
        error!("❌ Quick stress test FAILED (success rate: {:.1}%, clients/sec: {:.1})",
               result.success_rate, result.clients_per_second);
    }

    Ok(())
}

/// Интенсивный стресс-тест
pub async fn stress_test_intensive() -> Result<()> {
    info!("🔥 Running intensive stress test...");

    let config = StressTestConfig {
        total_clients: 500,
        max_concurrent: 100,
        packets_per_client: 20,
        packet_delay_ms: 20,
        test_duration_secs: 60,
        enable_random_delays: true,
        payload_sizes: vec![16, 64, 128, 256],
    };

    let result = run_stress_test(config).await?;

    if result.success_rate >= 80.0 && result.packets_per_second >= 100.0 {
        info!("✅ Intensive stress test PASSED");
    } else {
        error!("❌ Intensive stress test FAILED (success rate: {:.1}%, packets/sec: {:.1})",
               result.success_rate, result.packets_per_second);
    }

    Ok(())
}

/// Тест на стабильность соединений
pub async fn stability_test() -> Result<()> {
    info!("🧱 Running stability test...");

    let config = StressTestConfig {
        total_clients: 200,
        max_concurrent: 40,
        packets_per_client: 50,
        packet_delay_ms: 100,
        test_duration_secs: 120,
        enable_random_delays: false,
        payload_sizes: vec![32],
    };

    let result = run_stress_test(config).await?;

    if result.success_rate >= 95.0 {
        info!("✅ Stability test PASSED");
    } else {
        error!("❌ Stability test FAILED (success rate: {:.1}%)", result.success_rate);
    }

    Ok(())
}