#[derive(Debug, thiserror::Error)]
pub enum BatchError {
    #[error("Processing failed: {0}")]
    ProcessingFailed(String),

    #[error("Buffer full: {0}")]
    BufferFull(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("IO error: {0}")]
    IoError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

impl From<std::io::Error> for BatchError {
    fn from(err: std::io::Error) -> Self {
        BatchError::IoError(err.to_string())
    }
}