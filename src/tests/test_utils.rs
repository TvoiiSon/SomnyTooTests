use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use anyhow::Result;
use tracing::info;

use crate::config::CLIENT_CONFIG;
use crate::core::protocol::phantom_crypto::core::handshake::{perform_phantom_handshake, HandshakeRole};
use crate::core::protocol::phantom_crypto::core::keys::PhantomSession;

/// Establishes a connection and performs handshake
pub async fn establish_test_connection() -> Result<(
    Arc<PhantomSession>,
    tokio::net::tcp::OwnedReadHalf,
    tokio::net::tcp::OwnedWriteHalf
)> {
    let addr = CLIENT_CONFIG.server_addr();

    info!("🔗 Connecting to server for test...");

    let stream = tokio::time::timeout(
        Duration::from_millis(CLIENT_CONFIG.connect_timeout_ms),
        TcpStream::connect(&addr)
    ).await??;

    info!("✅ Connected to server");
    stream.set_nodelay(true)?;

    // Perform handshake
    let mut temp_stream = stream;
    let handshake_result = perform_phantom_handshake(
        &mut temp_stream,
        HandshakeRole::Client
    ).await?;

    let session = Arc::new(handshake_result.session);
    let (read_stream, write_stream) = temp_stream.into_split();

    info!("✅ Handshake completed for test");
    info!("🎯 Session ID: {}", hex::encode(session.session_id()));

    Ok((session, read_stream, write_stream))
}

/// Simple function to send a frame
pub async fn send_frame(write_stream: &mut (impl AsyncWriteExt + Unpin), data: &[u8]) -> Result<()> {
    let header = (data.len() as u32).to_be_bytes();

    write_stream.write_all(&header).await?;
    write_stream.write_all(data).await?;
    write_stream.flush().await?;

    Ok(())
}

/// Simple function to read a frame
pub async fn read_frame(read_stream: &mut (impl AsyncReadExt + Unpin)) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    read_stream.read_exact(&mut header).await?;

    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Ok(Vec::new());
    }

    let mut data = vec![0u8; length];
    read_stream.read_exact(&mut data).await?;

    Ok(data)
}

/// Closes connection gracefully
pub async fn close_connection(write_stream: &mut (impl AsyncWriteExt + Unpin)) {
    if let Err(e) = write_stream.shutdown().await {
        tracing::debug!("Test stream shutdown error: {}", e);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
}