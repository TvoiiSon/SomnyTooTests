use anyhow::Result;
use tracing::{info, debug};
use std::time::{Instant, Duration};
use tokio::net::TcpStream;

use crate::core::protocol::crypto::handshake::handshake::{perform_handshake, HandshakeRole};
use crate::core::protocol::packets::encoder::packet_builder::PacketBuilder;
use crate::core::protocol::packets::decoder::packet_parser::PacketParser;
use crate::core::protocol::packets::encoder::frame_writer::write_frame;
use crate::core::protocol::packets::decoder::frame_reader::read_frame;
use crate::test_client::TestClient;
use crate::test_server::TestServer;

/// Бенчмарк handshake и обработки пакетов с использованием TestClient/TestServer
pub async fn benchmark_handshake_and_processing() -> Result<BenchmarkResults> {
    // Запускаем локальный тестовый сервер
    let server = TestServer::spawn().await;
    info!("Test server started on {}", server.addr);

    let mut results = BenchmarkResults::new();

    // 1. Измерение времени подключения TCP (через TestClient)
    let connect_start = Instant::now();
    let mut client = TestClient::connect().await?;
    let connect_time = connect_start.elapsed();
    results.connect_time = connect_time;
    info!("TCP connect + handshake (через TestClient): {:?}", connect_time);

    // Дополнительно: извлекаем session_id из уже установленного соединения
    let session_keys = client.ctx;
    info!("Session ID: {}", hex::encode(&session_keys.session_id));

    // 2. Измерение времени шифрования пакета
    let encrypt_start = Instant::now();
    let test_payload = b"Test payload for benchmark";
    let encrypted_packet = PacketBuilder::build_encrypted_packet(&session_keys, 0x01, test_payload).await;
    let encrypt_time = encrypt_start.elapsed();
    results.encryption_time = encrypt_time;
    info!("Encryption time: {:?}", encrypt_time);
    debug!("Encrypted packet size: {} bytes", encrypted_packet.len());

    // 3. Измерение времени отправки пакета
    let send_start = Instant::now();
    write_frame(&mut client.stream, &encrypted_packet).await?;
    let send_time = send_start.elapsed();
    results.send_time = send_time;
    info!("Send time: {:?}", send_time);

    // 4. Измерение времени получения ответа (RTT)
    let receive_start = Instant::now();
    let response_frame = read_frame(&mut client.stream).await?;
    let receive_time = receive_start.elapsed();
    results.receive_time = receive_time;
    info!("Receive time (RTT): {:?}", receive_time);

    // 5. Измерение времени расшифровки ответа
    let decrypt_start = Instant::now();
    let (packet_type, plaintext) = PacketParser::decode_packet(&session_keys, &response_frame)?;
    let decrypt_time = decrypt_start.elapsed();
    results.decryption_time = decrypt_time;
    info!("Decryption time: {:?}", decrypt_time);
    debug!("Response packet type: {}, plaintext: {} bytes", packet_type, plaintext.len());

    // 6. Общее время (от подключения до получения ответа)
    let total_time = connect_start.elapsed();
    results.total_time = total_time;

    // 7. Оценка времени обработки на сервере
    // RTT минус локальные операции клиента
    let estimated_server_processing = receive_time.saturating_sub(
        encrypt_time + send_time + decrypt_time
    );
    results.estimated_server_processing_time = estimated_server_processing;

    // 8. Разделяем handshake время (оценка)
    // В TestClient.connect() уже включает handshake, поэтому вычитаем TCP connect
    // Это грубая оценка, но лучше чем ничего
    let estimated_handshake_time = connect_time.saturating_sub(Duration::from_millis(1)); // Примерная поправка
    results.handshake_time = estimated_handshake_time;

    results.print_summary();

    Ok(results)
}

/// Более точный бенчмарк с раздельным измерением handshake
pub async fn benchmark_detailed() -> Result<DetailedBenchmarkResults> {
    let server = TestServer::spawn().await;
    info!("Test server started on {}", server.addr);

    let mut results = DetailedBenchmarkResults::new();

    // Этап 1: TCP подключение (без handshake)
    let tcp_connect_start = Instant::now();
    let mut stream = TcpStream::connect(&server.addr).await?;
    let tcp_connect_time = tcp_connect_start.elapsed();
    results.tcp_connect_time = tcp_connect_time;
    info!("Pure TCP connect time: {:?}", tcp_connect_time);

    // Этап 2: Handshake
    let handshake_start = Instant::now();
    let handshake_result = perform_handshake(&mut stream, HandshakeRole::Client).await?;
    let handshake_time = handshake_start.elapsed();
    results.handshake_time = handshake_time;

    let session_keys = handshake_result.session_keys;
    info!("Handshake time: {:?}", handshake_time);
    info!("Session ID: {}", hex::encode(&session_keys.session_id));

    // Создаем TestClient из существующего соединения
    let client = TestClient {
        stream,
        ctx: session_keys.clone(),
    };

    // Дальнейшие измерения как в обычном бенчмарке
    let benchmark_results = benchmark_with_existing_client(client, session_keys).await?;

    // Объединяем результаты
    results.merge_basic_results(benchmark_results);

    results.print_detailed_summary();

    Ok(results)
}

/// Бенчмарк с существующим клиентом (для повторного использования)
async fn benchmark_with_existing_client(
    mut client: TestClient,
    session_keys: crate::core::protocol::crypto::key_manager::session_keys::SessionKeys,
) -> Result<BenchmarkResults> {
    let mut results = BenchmarkResults::new();

    // Измерение времени шифрования пакета
    let encrypt_start = Instant::now();
    let test_payload = b"";
    let encrypted_packet = PacketBuilder::build_encrypted_packet(&session_keys, 0x01, test_payload).await;
    let encrypt_time = encrypt_start.elapsed();
    results.encryption_time = encrypt_time;

    // Измерение времени отправки пакета
    let send_start = Instant::now();
    write_frame(&mut client.stream, &encrypted_packet).await?;
    let send_time = send_start.elapsed();
    results.send_time = send_time;

    // Измерение времени получения ответа
    let receive_start = Instant::now();
    let response_frame = read_frame(&mut client.stream).await?;
    let receive_time = receive_start.elapsed();
    results.receive_time = receive_time;

    // Измерение времени расшифровки
    let decrypt_start = Instant::now();
    let (_packet_type, _plaintext) = PacketParser::decode_packet(&session_keys, &response_frame)?;
    let decrypt_time = decrypt_start.elapsed();
    results.decryption_time = decrypt_time;

    // Оценка времени обработки на сервере
    let estimated_server_processing = receive_time.saturating_sub(
        encrypt_time + send_time + decrypt_time
    );
    results.estimated_server_processing_time = estimated_server_processing;

    // Общее время для этого этапа
    results.total_time = encrypt_start.elapsed();

    Ok(results)
}

/// Многократный бенчмарк для статистики
pub async fn benchmark_multiple_iterations(iterations: usize) -> Result<AggregatedResults> {
    let mut all_results = Vec::new();

    for i in 0..iterations {
        info!("Running benchmark iteration {}/{}", i + 1, iterations);

        match benchmark_handshake_and_processing().await {
            Ok(results) => {
                all_results.push(results);
                // Пауза между итерациями
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => {
                info!("Iteration {} failed: {}", i + 1, e);
            }
        }
    }

    let aggregated = AggregatedResults::from_results(&all_results);
    aggregated.print_summary();

    Ok(aggregated)
}

/// Детальный многократный бенчмарк
pub async fn benchmark_detailed_multiple(iterations: usize) -> Result<DetailedAggregatedResults> {
    let mut all_results = Vec::new();

    for i in 0..iterations {
        info!("Running detailed benchmark iteration {}/{}", i + 1, iterations);

        match benchmark_detailed().await {
            Ok(results) => {
                all_results.push(results);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => {
                info!("Detailed iteration {} failed: {}", i + 1, e);
            }
        }
    }

    let aggregated = DetailedAggregatedResults::from_results(&all_results);
    aggregated.print_summary();

    Ok(aggregated)
}

#[derive(Debug, Clone)]
pub struct BenchmarkResults {
    pub connect_time: Duration,  // Включает TCP connect + handshake
    pub handshake_time: Duration,
    pub encryption_time: Duration,
    pub send_time: Duration,
    pub receive_time: Duration,
    pub decryption_time: Duration,
    pub total_time: Duration,
    pub estimated_server_processing_time: Duration,
}

impl BenchmarkResults {
    pub fn new() -> Self {
        Self {
            connect_time: Duration::default(),
            handshake_time: Duration::default(),
            encryption_time: Duration::default(),
            send_time: Duration::default(),
            receive_time: Duration::default(),
            decryption_time: Duration::default(),
            total_time: Duration::default(),
            estimated_server_processing_time: Duration::default(),
        }
    }

    pub fn print_summary(&self) {
        info!("=== BENCHMARK RESULTS ===");
        info!("Connect (TCP+Handshake): {:?}", self.connect_time);
        info!("Estimated Handshake:     {:?}", self.handshake_time);
        info!("Encryption:              {:?}", self.encryption_time);
        info!("Send:                    {:?}", self.send_time);
        info!("Receive (RTT):           {:?}", self.receive_time);
        info!("Decryption:              {:?}", self.decryption_time);
        info!("Total:                   {:?}", self.total_time);
        info!("Estimated server processing: {:?}", self.estimated_server_processing_time);
        info!("========================");
    }
}

#[derive(Debug, Clone)]
pub struct DetailedBenchmarkResults {
    pub tcp_connect_time: Duration,
    pub handshake_time: Duration,
    pub encryption_time: Duration,
    pub send_time: Duration,
    pub receive_time: Duration,
    pub decryption_time: Duration,
    pub total_time: Duration,
    pub estimated_server_processing_time: Duration,
}

impl DetailedBenchmarkResults {
    pub fn new() -> Self {
        Self {
            tcp_connect_time: Duration::default(),
            handshake_time: Duration::default(),
            encryption_time: Duration::default(),
            send_time: Duration::default(),
            receive_time: Duration::default(),
            decryption_time: Duration::default(),
            total_time: Duration::default(),
            estimated_server_processing_time: Duration::default(),
        }
    }

    pub fn merge_basic_results(&mut self, basic: BenchmarkResults) {
        self.encryption_time = basic.encryption_time;
        self.send_time = basic.send_time;
        self.receive_time = basic.receive_time;
        self.decryption_time = basic.decryption_time;
        self.estimated_server_processing_time = basic.estimated_server_processing_time;
        self.total_time = self.tcp_connect_time + self.handshake_time + basic.total_time;
    }

    pub fn print_detailed_summary(&self) {
        info!("=== DETAILED BENCHMARK RESULTS ===");
        info!("TCP Connect (pure):      {:?}", self.tcp_connect_time);
        info!("Handshake (crypto):      {:?}", self.handshake_time);
        info!("Total connection:        {:?}", self.tcp_connect_time + self.handshake_time);
        info!("Encryption:              {:?}", self.encryption_time);
        info!("Send:                    {:?}", self.send_time);
        info!("Receive (RTT):           {:?}", self.receive_time);
        info!("Decryption:              {:?}", self.decryption_time);
        info!("Estimated server processing: {:?}", self.estimated_server_processing_time);
        info!("Total overall:           {:?}", self.total_time);
        info!("================================");
    }
}

#[derive(Debug)]
pub struct AggregatedResults {
    pub iterations: usize,
    pub avg_connect_time: Duration,
    pub avg_handshake_time: Duration,
    pub avg_encryption_time: Duration,
    pub avg_send_time: Duration,
    pub avg_receive_time: Duration,
    pub avg_decryption_time: Duration,
    pub avg_total_time: Duration,
    pub avg_server_processing_time: Duration,
    pub min_total_time: Duration,
    pub max_total_time: Duration,
}

impl AggregatedResults {
    pub fn from_results(results: &[BenchmarkResults]) -> Self {
        if results.is_empty() {
            return Self::default();
        }

        let iterations = results.len();

        // Вычисляем средние значения
        let avg_connect_time = results.iter()
            .map(|r| r.connect_time)
            .sum::<Duration>() / iterations as u32;

        let avg_handshake_time = results.iter()
            .map(|r| r.handshake_time)
            .sum::<Duration>() / iterations as u32;

        let avg_encryption_time = results.iter()
            .map(|r| r.encryption_time)
            .sum::<Duration>() / iterations as u32;

        let avg_send_time = results.iter()
            .map(|r| r.send_time)
            .sum::<Duration>() / iterations as u32;

        let avg_receive_time = results.iter()
            .map(|r| r.receive_time)
            .sum::<Duration>() / iterations as u32;

        let avg_decryption_time = results.iter()
            .map(|r| r.decryption_time)
            .sum::<Duration>() / iterations as u32;

        let avg_total_time = results.iter()
            .map(|r| r.total_time)
            .sum::<Duration>() / iterations as u32;

        let avg_server_processing_time = results.iter()
            .map(|r| r.estimated_server_processing_time)
            .sum::<Duration>() / iterations as u32;

        // Находим мин/макс
        let min_total_time = results.iter()
            .map(|r| r.total_time)
            .min()
            .unwrap_or_default();

        let max_total_time = results.iter()
            .map(|r| r.total_time)
            .max()
            .unwrap_or_default();

        Self {
            iterations,
            avg_connect_time,
            avg_handshake_time,
            avg_encryption_time,
            avg_send_time,
            avg_receive_time,
            avg_decryption_time,
            avg_total_time,
            avg_server_processing_time,
            min_total_time,
            max_total_time,
        }
    }

    pub fn print_summary(&self) {
        info!("=== AGGREGATED BENCHMARK RESULTS ({} iterations) ===", self.iterations);
        info!("Average Connect (TCP+Handshake): {:?}", self.avg_connect_time);
        info!("Average Handshake (estimated):   {:?}", self.avg_handshake_time);
        info!("Average Encryption:              {:?}", self.avg_encryption_time);
        info!("Average Send:                    {:?}", self.avg_send_time);
        info!("Average Receive (RTT):           {:?}", self.avg_receive_time);
        info!("Average Decryption:              {:?}", self.avg_decryption_time);
        info!("Average Total:                   {:?}", self.avg_total_time);
        info!("Average Server processing:       {:?}", self.avg_server_processing_time);
        info!("Min Total Time:                  {:?}", self.min_total_time);
        info!("Max Total Time:                  {:?}", self.max_total_time);
        info!("==================================================");
    }
}

#[derive(Debug)]
pub struct DetailedAggregatedResults {
    pub iterations: usize,
    pub avg_tcp_connect_time: Duration,
    pub avg_handshake_time: Duration,
    pub avg_encryption_time: Duration,
    pub avg_send_time: Duration,
    pub avg_receive_time: Duration,
    pub avg_decryption_time: Duration,
    pub avg_total_time: Duration,
    pub avg_server_processing_time: Duration,
}

impl DetailedAggregatedResults {
    pub fn from_results(results: &[DetailedBenchmarkResults]) -> Self {
        if results.is_empty() {
            return Self::default();
        }

        let iterations = results.len();

        let avg_tcp_connect_time = results.iter()
            .map(|r| r.tcp_connect_time)
            .sum::<Duration>() / iterations as u32;

        let avg_handshake_time = results.iter()
            .map(|r| r.handshake_time)
            .sum::<Duration>() / iterations as u32;

        let avg_encryption_time = results.iter()
            .map(|r| r.encryption_time)
            .sum::<Duration>() / iterations as u32;

        let avg_send_time = results.iter()
            .map(|r| r.send_time)
            .sum::<Duration>() / iterations as u32;

        let avg_receive_time = results.iter()
            .map(|r| r.receive_time)
            .sum::<Duration>() / iterations as u32;

        let avg_decryption_time = results.iter()
            .map(|r| r.decryption_time)
            .sum::<Duration>() / iterations as u32;

        let avg_total_time = results.iter()
            .map(|r| r.total_time)
            .sum::<Duration>() / iterations as u32;

        let avg_server_processing_time = results.iter()
            .map(|r| r.estimated_server_processing_time)
            .sum::<Duration>() / iterations as u32;

        Self {
            iterations,
            avg_tcp_connect_time,
            avg_handshake_time,
            avg_encryption_time,
            avg_send_time,
            avg_receive_time,
            avg_decryption_time,
            avg_total_time,
            avg_server_processing_time,
        }
    }

    pub fn print_summary(&self) {
        info!("=== DETAILED AGGREGATED RESULTS ({} iterations) ===", self.iterations);
        info!("Average TCP Connect (pure):      {:?}", self.avg_tcp_connect_time);
        info!("Average Handshake (crypto):      {:?}", self.avg_handshake_time);
        info!("Average connection total:        {:?}", self.avg_tcp_connect_time + self.avg_handshake_time);
        info!("Average Encryption:              {:?}", self.avg_encryption_time);
        info!("Average Send:                    {:?}", self.avg_send_time);
        info!("Average Receive (RTT):           {:?}", self.avg_receive_time);
        info!("Average Decryption:              {:?}", self.avg_decryption_time);
        info!("Average Server processing:       {:?}", self.avg_server_processing_time);
        info!("Average Total overall:           {:?}", self.avg_total_time);
        info!("==================================================");
    }
}

impl Default for AggregatedResults {
    fn default() -> Self {
        Self {
            iterations: 0,
            avg_connect_time: Duration::default(),
            avg_handshake_time: Duration::default(),
            avg_encryption_time: Duration::default(),
            avg_send_time: Duration::default(),
            avg_receive_time: Duration::default(),
            avg_decryption_time: Duration::default(),
            avg_total_time: Duration::default(),
            avg_server_processing_time: Duration::default(),
            min_total_time: Duration::default(),
            max_total_time: Duration::default(),
        }
    }
}

impl Default for DetailedAggregatedResults {
    fn default() -> Self {
        Self {
            iterations: 0,
            avg_tcp_connect_time: Duration::default(),
            avg_handshake_time: Duration::default(),
            avg_encryption_time: Duration::default(),
            avg_send_time: Duration::default(),
            avg_receive_time: Duration::default(),
            avg_decryption_time: Duration::default(),
            avg_total_time: Duration::default(),
            avg_server_processing_time: Duration::default(),
        }
    }
}