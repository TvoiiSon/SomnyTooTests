// tests/helpers/test_utils.rs
use std::time::{Duration, Instant};
use tokio::time;

/// Утилиты для тестирования через клиент
pub struct TestClientUtils;

impl TestClientUtils {
    /// Запускает тест с таймаутом
    pub async fn run_with_timeout<F, T>(
        timeout: Duration,
        test_fn: F
    ) -> anyhow::Result<T>
    where
        F: std::future::Future<Output = anyhow::Result<T>>,
    {
        match time::timeout(timeout, test_fn).await {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!("Тест превысил таймаут {:?}", timeout)),
        }
    }

    /// Проверяет что операция завершается за указанное время
    pub async fn assert_completes_within<F>(
        max_duration: Duration,
        operation: F
    ) -> anyhow::Result<()>
    where
        F: std::future::Future<Output = anyhow::Result<()>>,
    {
        let start = Instant::now();
        operation.await?;
        let elapsed = start.elapsed();

        if elapsed > max_duration {
            Err(anyhow::anyhow!(
                "Операция заняла {:?}, максимум {:?}",
                elapsed,
                max_duration
            ))
        } else {
            Ok(())
        }
    }
}

/// Сборщик метрик для тестов
#[derive(Default)]
pub struct TestMetrics {
    pub total_tests: usize,
    pub passed_tests: usize,
    pub failed_tests: usize,
    pub total_duration: Duration,
}

impl TestMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_test(&mut self, success: bool, duration: Duration) {
        self.total_tests += 1;
        self.total_duration += duration;

        if success {
            self.passed_tests += 1;
        } else {
            self.failed_tests += 1;
        }
    }

    pub fn print_summary(&self) {
        println!("\n📊 Сводка тестирования:");
        println!("  Всего тестов: {}", self.total_tests);
        println!("  Успешно: {}", self.passed_tests);
        println!("  Неудачно: {}", self.failed_tests);
        println!("  Общее время: {:?}", self.total_duration);

        if self.total_tests > 0 {
            let avg_time = self.total_duration / self.total_tests as u32;
            println!("  Среднее время теста: {:?}", avg_time);

            let success_rate = self.passed_tests as f64 / self.total_tests as f64 * 100.0;
            println!("  Уровень успешности: {:.1}%", success_rate);
        }
    }
}