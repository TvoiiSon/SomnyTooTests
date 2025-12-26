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

// Глобальный конфиг (опционально, для удобства)
lazy_static::lazy_static! {
    pub static ref CONFIG: Config = Config::from_env()
        .expect("Не удалось загрузить конфигурацию из .env файла");
}