use dotenv::dotenv;
use tracing_subscriber::{FmtSubscriber, EnvFilter};
use somnytoo_test::tests::send_ping_packet::send_ping_packet;
use somnytoo_test::tests::test_benchmark::{benchmark_detailed, benchmark_detailed_multiple, benchmark_multiple_iterations, benchmark_handshake_and_processing};

#[tokio::main]
async fn main() {
    dotenv().ok();

    // Инициализация logging
    init_logging();

    let _ = send_ping_packet().await;

    // let _ = benchmark_handshake_and_processing().await;
    // let _ = benchmark_detailed().await;
    // let _ = benchmark_detailed_multiple(3).await;
    // let _ = benchmark_multiple_iterations(3).await;
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("debug"));

    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter)
        .with_target(true)
        .with_level(true)
        .with_ansi(true)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");
}