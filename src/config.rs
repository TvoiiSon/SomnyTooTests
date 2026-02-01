use std::env;
use anyhow::{Result, Context};
use lazy_static::lazy_static;

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub server_host: String,
    pub server_port: u16,
    pub connect_timeout_ms: u64,
    pub batch_size: usize,
    pub flush_interval_ms: u64,
    pub max_buffer_size: usize,
}

impl ClientConfig {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            server_host: env::var("SERVER_HOST")
                .unwrap_or_else(|_| "127.0.0.1".to_string()),
            server_port: env::var("SERVER_PORT")
                .unwrap_or_else(|_| "8000".to_string())
                .parse::<u16>()
                .context("SERVER_PORT должен быть числом")?,
            connect_timeout_ms: env::var("CONNECT_TIMEOUT_MS")
                .unwrap_or_else(|_| "10000".to_string())
                .parse::<u64>()
                .unwrap_or(10000),
            batch_size: env::var("CLIENT_BATCH_SIZE")
                .unwrap_or_else(|_| "16".to_string())
                .parse::<usize>()
                .unwrap_or(16),
            flush_interval_ms: env::var("CLIENT_FLUSH_INTERVAL_MS")
                .unwrap_or_else(|_| "100".to_string())
                .parse::<u64>()
                .unwrap_or(100),
            max_buffer_size: env::var("CLIENT_MAX_BUFFER_SIZE")
                .unwrap_or_else(|_| "1048576".to_string()) // 1 MB
                .parse::<usize>()
                .unwrap_or(1024 * 1024),
        })
    }

    pub fn server_addr(&self) -> String {
        format!("{}:{}", self.server_host, self.server_port)
    }
}

lazy_static! {
    pub static ref CLIENT_CONFIG: ClientConfig = ClientConfig::from_env()
        .unwrap_or_else(|_| ClientConfig {
            server_host: "127.0.0.1".to_string(),
            server_port: 8000,
            connect_timeout_ms: 10000,
            batch_size: 16,
            flush_interval_ms: 100,
            max_buffer_size: 1024 * 1024,
        });
}