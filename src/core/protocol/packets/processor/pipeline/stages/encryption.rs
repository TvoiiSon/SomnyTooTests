use async_trait::async_trait;
use tracing::info;
use crate::core::protocol::packets::encoder::packet_builder::PacketBuilder;

use super::common::{PipelineStage, PipelineContext, StageError};

pub struct EncryptionStage;

impl EncryptionStage {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl PipelineStage for EncryptionStage {
    async fn execute(&self, context: &mut PipelineContext) -> Result<(), StageError> {
        let processed_data = context.processed_data
            .take()
            .ok_or_else(|| StageError::EncryptionFailed("No processed data available".to_string()))?;

        // ЕСЛИ ОТВЕТ ПУСТОЙ - НЕ СОЗДАЕМ ЗАШИФРОВАННЫЙ ПАКЕТ
        if processed_data.is_empty() {
            info!("🛑 Пустой ответ, пропускаем шифрование");
            context.encrypted_response = Some(vec![]);
            return Ok(());
        }

        info!("🔒 Шифрование ответа размером {} байт", processed_data.len());

        // Для ответов используем тип Pong (0x01)
        let response_packet_type = 0x01;

        let encrypted_response = PacketBuilder::build_encrypted_packet(
            &context.session_keys,
            response_packet_type,
            &processed_data,
        ).await;

        context.encrypted_response = Some(encrypted_response);
        Ok(())
    }
}