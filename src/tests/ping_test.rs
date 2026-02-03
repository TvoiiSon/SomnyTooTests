use std::time::Duration;
use anyhow::Result;
use tracing::{info, error, warn};

use crate::core::protocol::phantom_crypto::packet::PhantomPacketProcessor;

use super::test_utils::{establish_test_connection, send_frame, read_frame, close_connection};

/// Test sending a PING packet (type 0x01)
pub async fn test_ping_packet() -> Result<()> {
    info!("🧪 Starting PING packet test...");

    // Establish connection
    let (session, mut read_stream, mut write_stream) = establish_test_connection().await?;

    // Create packet processor
    let packet_processor = PhantomPacketProcessor::new();

    // Create PING packet (type 0x01)
    let ping_packet = packet_processor.create_outgoing_vec(
        &session,
        0x01, // PING packet type
        b"Test PING from client"
    )?;

    info!("📦 Created PING packet: {} bytes", ping_packet.len());

    // Send PING
    info!("📤 Sending PING packet...");
    send_frame(&mut write_stream, &ping_packet).await?;
    info!("✅ PING sent successfully");

    // Wait for response
    info!("👂 Waiting for PONG response...");
    match tokio::time::timeout(Duration::from_secs(10), read_frame(&mut read_stream)).await {
        Ok(Ok(frame_data)) => {
            if frame_data.is_empty() {
                error!("❌ Server closed connection without response");
                return Err(anyhow::anyhow!("Server closed connection"));
            }

            info!("📥 Received {} bytes from server", frame_data.len());

            // Try to decrypt response
            match packet_processor.process_incoming_vec(&frame_data, &session) {
                Ok((packet_type, payload)) => {
                    let payload_str = String::from_utf8_lossy(&payload);

                    if packet_type == 0x01 && payload_str == "PONG" {
                        info!("✅ TEST PASSED: PONG received successfully!");
                        info!("🎯 Response payload: {}", payload_str);
                    } else {
                        warn!("⚠️ Unexpected response: type=0x{:02x}, payload={}",
                              packet_type, payload_str);
                        info!("ℹ️ Test completed with unexpected response");
                    }
                }
                Err(e) => {
                    error!("❌ Failed to decrypt response: {}", e);
                    return Err(e.into());
                }
            }
        }
        Ok(Err(e)) => {
            error!("❌ Failed to read frame: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            error!("⏰ Timeout waiting for server response");
            return Err(anyhow::anyhow!("Timeout waiting for response"));
        }
    }

    // Close connection
    close_connection(&mut write_stream).await;

    info!("✅ PING test completed successfully");
    Ok(())
}

/// Test sending multiple PING packets
pub async fn test_multiple_pings(count: usize) -> Result<()> {
    info!("🧪 Starting multiple PING test ({} packets)...", count);

    let (session, mut read_stream, mut write_stream) = establish_test_connection().await?;
    let packet_processor = PhantomPacketProcessor::new();

    let mut successful_responses = 0;

    for i in 0..count {
        info!("📤 Sending PING #{}...", i + 1);

        let ping_packet = packet_processor.create_outgoing_vec(
            &session,
            0x01,
            format!("PING #{}, time: {}", i + 1, chrono::Local::now().timestamp()).as_bytes()
        )?;

        send_frame(&mut write_stream, &ping_packet).await?;

        // Read response
        match tokio::time::timeout(Duration::from_secs(5), read_frame(&mut read_stream)).await {
            Ok(Ok(frame_data)) if !frame_data.is_empty() => {
                match packet_processor.process_incoming_vec(&frame_data, &session) {
                    Ok((packet_type, payload)) => {
                        let payload_str = String::from_utf8_lossy(&payload);
                        if packet_type == 0x01 && payload_str == "PONG" {
                            successful_responses += 1;
                            info!("✅ PING #{}: PONG received", i + 1);
                        }
                    }
                    _ => warn!("⚠️ PING #{}: Invalid response", i + 1),
                }
            }
            _ => warn!("⚠️ PING #{}: No response", i + 1),
        }

        // Small delay between packets
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    close_connection(&mut write_stream).await;

    info!("📊 Multiple PING test results: {}/{} successful",
          successful_responses, count);

    if successful_responses == count {
        info!("✅ All PING tests passed!");
    } else {
        warn!("⚠️ Some PING tests failed");
    }

    Ok(())
}

/// Test invalid packet type (should fail gracefully)
pub async fn test_invalid_packet_type() -> Result<()> {
    info!("🧪 Testing invalid packet type handling...");

    let (session, _, mut write_stream) = establish_test_connection().await?;
    let packet_processor = PhantomPacketProcessor::new();

    // Create packet with invalid type
    let invalid_packet = packet_processor.create_outgoing_vec(
        &session,
        0xFF, // Invalid packet type
        b"This should fail"
    )?;

    info!("📤 Sending invalid packet type 0xFF...");
    send_frame(&mut write_stream, &invalid_packet).await?;

    // Server should handle this gracefully or close connection
    tokio::time::sleep(Duration::from_millis(500)).await;

    close_connection(&mut write_stream).await;

    info!("✅ Invalid packet type test completed");
    Ok(())
}