use std::time::Duration;
use anyhow::Result;
use tracing_subscriber::{FmtSubscriber, EnvFilter};
use tracing::{info, error, warn};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Run ping test
    #[arg(short, long)]
    test_ping: bool,

    /// Run multiple ping test with specified count
    #[arg(short = 'm', long, value_name = "COUNT")]
    multiple_pings: Option<usize>,

    /// Run all tests
    #[arg(short = 'a', long)]
    all_tests: bool,

    /// Run integration test
    #[arg(short = 'i', long)]
    integration: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Настройка логирования
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            let mut filter = EnvFilter::new("info");
            filter = filter.add_directive("tokio=warn".parse().unwrap());
            filter = filter.add_directive("runtime=warn".parse().unwrap());
            filter = filter.add_directive("tracing=warn".parse().unwrap());
            filter
        });

    let subscriber = FmtSubscriber::builder()
        .with_env_filter(filter)
        .with_target(true)
        .with_level(true)
        .without_time()
        .compact()
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    let args = Args::parse();

    // Check if we're running tests
    if args.test_ping || args.multiple_pings.is_some() || args.all_tests || args.integration {
        run_tests(args).await
    } else {
        // Original client functionality
        run_client().await
    }
}

async fn run_tests(args: Args) -> Result<()> {
    info!("🧪 Running tests...");

    let mut test_results: Vec<String> = Vec::new();

    // Single ping test
    if args.test_ping || args.all_tests {
        info!("\n📋 Running single PING test...");
        match somnytoo_test::tests::ping_test::test_ping_packet().await {
            Ok(_) => {
                info!("✅ Single PING test: PASSED");
                test_results.push("Single PING: PASSED".to_string());
            }
            Err(e) => {
                error!("❌ Single PING test: FAILED - {}", e);
                test_results.push(format!("Single PING: FAILED - {}", e));
            }
        }
    }

    // Multiple ping test
    if let Some(count) = args.multiple_pings {
        info!("\n📋 Running multiple PING test ({} packets)...", count);
        match somnytoo_test::tests::ping_test::test_multiple_pings(count).await {
            Ok(_) => {
                info!("✅ Multiple PING test: PASSED");
                test_results.push(format!("Multiple PING ({}): PASSED", count));
            }
            Err(e) => {
                error!("❌ Multiple PING test: FAILED - {}", e);
                test_results.push(format!("Multiple PING ({}): FAILED - {}", count, e));
            }
        }
    }

    // Integration test (basic client functionality)
    if args.integration || args.all_tests {
        info!("\n📋 Running integration test (full client flow)...");
        match run_client().await {
            Ok(_) => {
                info!("✅ Integration test: PASSED");
                test_results.push("Integration: PASSED".to_string());
            }
            Err(e) => {
                error!("❌ Integration test: FAILED - {}", e);
                test_results.push(format!("Integration: FAILED - {}", e));
            }
        }
    }

    // Print summary
    info!("\n📊 Test Summary:");
    info!("{}", "=".repeat(50));
    for result in &test_results {
        info!("{}", result);
    }
    info!("{}", "=".repeat(50));

    Ok(())
}

async fn run_client() -> Result<()> {
    use somnytoo_test::tests::test_utils::*;

    let (session, mut read_stream, mut write_stream) = establish_test_connection().await?;
    let packet_processor = somnytoo_test::core::protocol::phantom_crypto::packet::PhantomPacketProcessor::new();

    // Создаем PING пакет
    let ping_packet = packet_processor.create_outgoing_vec(
        &session,
        0x01,
        b"PING from client"
    )?;

    info!("📦 Created PING packet: {} bytes", ping_packet.len());
    info!("📤 Sending PING packet...");

    send_frame(&mut write_stream, &ping_packet).await?;
    info!("✅ PING sent successfully");

    // Читаем ответ
    match tokio::time::timeout(Duration::from_secs(10), read_frame(&mut read_stream)).await {
        Ok(Ok(frame_data)) if !frame_data.is_empty() => {
            info!("📥 Received {} bytes from server", frame_data.len());

            match packet_processor.process_incoming_vec(&frame_data, &session) {
                Ok((packet_type, payload)) => {
                    let payload_str = String::from_utf8_lossy(&payload);
                    if packet_type == 0x01 && payload_str == "PONG" {
                        info!("✅ PONG received successfully!");
                        info!("🎉 Mission accomplished!");
                    }
                }
                _ => warn!("⚠️ Failed to process response"),
            }
        }
        _ => error!("❌ No response from server"),
    }

    close_connection(&mut write_stream).await;
    info!("👋 Client shutdown complete");

    Ok(())
}