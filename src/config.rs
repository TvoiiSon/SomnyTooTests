use std::env;
use anyhow::{Result, Context};

#[derive(Debug, Clone)]
pub struct Config {
    pub server_host: String,
    pub server_port: u16,
    pub hmac_secret_key: String,
    pub aes_secret_key: String,
    pub psk_secret: String,
}

#[derive(Debug, Clone)]
pub struct PhantomConfig {
    pub enable_hardware_auth: bool,
    pub session_timeout_ms: u64,
    pub max_sessions: usize,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            server_host: env::var("SERVER_HOST")
                .context("SERVER_HOST не установлен в .env")?,
            server_port: env::var("SERVER_PORT")
                .context("SERVER_PORT не установлен в .env")?
                .parse()
                .context("SERVER_PORT должен быть числом")?,
            hmac_secret_key: env::var("HMAC_SECRET_KEY")
                .context("HMAC_SECRET_KEY не установлен в .env")?,
            aes_secret_key: env::var("AES_SECRET_KEY")
                .context("AES_SECRET_KEY не установлен в .env")?,
            psk_secret: env::var("PSK_SECRET")
                .context("PSK_SECRET не установлен в .env")?,
        })
    }

    pub fn server_addr(&self) -> String {
        format!("{}:{}", self.server_host, self.server_port)
    }
}

impl PhantomConfig {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            enable_hardware_auth: env::var("PHANTOM_HARDWARE_AUTH")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
            session_timeout_ms: env::var("PHANTOM_SESSION_TIMEOUT_MS")
                .unwrap_or_else(|_| "90000".to_string())
                .parse()
                .unwrap_or(90000),
            max_sessions: env::var("PHANTOM_MAX_SESSIONS")
                .unwrap_or_else(|_| "100000".to_string())
                .parse()
                .unwrap_or(100000),
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.max_sessions == 0 {
            anyhow::bail!("PHANTOM_MAX_SESSIONS must be greater than 0");
        }
        if self.session_timeout_ms == 0 {
            anyhow::bail!("PHANTOM_SESSION_TIMEOUT_MS must be greater than 0");
        }
        Ok(())
    }

    pub fn should_use_hardware_auth(&self) -> bool {
        self.enable_hardware_auth
    }
}

// Глобальный конфиг (опционально, для удобства)
lazy_static::lazy_static! {
    pub static ref CONFIG: Config = Config::from_env()
        .expect("Не удалось загрузить конфигурацию из .env файла");
    pub static ref PHANTOM_CONFIG: PhantomConfig = PhantomConfig::from_env()
        .unwrap_or_default();
}

impl Default for PhantomConfig {
    fn default() -> Self {
        Self {
            enable_hardware_auth: false,
            session_timeout_ms: 90_000,
            max_sessions: 100_000,
        }
    }
}