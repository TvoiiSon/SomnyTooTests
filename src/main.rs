use dotenv::dotenv;
use tracing_subscriber::{FmtSubscriber, EnvFilter};
use somnytoo_test::tests::send_ping_packet::send_ping_packet;

#[tokio::main] // Добавьте этот атрибут
async fn main() {
    dotenv().ok();

    // Инициализация logging
    init_logging();

    let _ = send_ping_packet().await;
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