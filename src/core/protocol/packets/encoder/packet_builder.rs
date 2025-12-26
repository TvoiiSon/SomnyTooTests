use aes_gcm::{
    aead::{Aead, Payload}
};
use generic_array::GenericArray;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand::RngCore;
use rand_core::OsRng;
use tokio::task;
use tracing::{info, trace, debug};

use crate::core::protocol::crypto::key_manager::session_keys::SessionKeys;

const HEADER_MAGIC: [u8;2] = [0xAB,0xCD];
const SIGNATURE_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

type HmacSha256 = Hmac<Sha256>;

pub struct PacketBuilder;

impl PacketBuilder {
    pub async fn build_encrypted_packet(
        ctx: &SessionKeys,
        packet_type: u8,
        plaintext: &[u8]
    ) -> Vec<u8> {
        // Логируем начало создания пакета
        info!(
            target: "packet_builder",
            "Starting encrypted packet build - type: 0x{:02X}, plaintext_len: {}, session_id: {}",
            packet_type,
            plaintext.len(),
            hex::encode(&ctx.session_id)
        );

        // Копируем все необходимые данные для передачи в blocking task
        let ctx_clone = ctx.clone();
        let plaintext_clone = plaintext.to_vec();
        let packet_type_clone = packet_type;

        let start_time = std::time::Instant::now();

        let result = task::spawn_blocking(move || {
            let thread_start = std::time::Instant::now();

            info!(
                target: "packet_builder",
                "Blocking task started - type: 0x{:02X}, plaintext_len: {}",
                packet_type_clone,
                plaintext_clone.len()
            );

            let mut nonce_bytes = [0u8; NONCE_SIZE];
            OsRng.fill_bytes(&mut nonce_bytes);

            // Логируем сгенерированный nonce
            trace!(
                target: "packet_builder",
                "Nonce generated: {}",
                hex::encode(&nonce_bytes)
            );

            // Определяем AAD
            let ciphertext_len = plaintext_clone.len() + 16;
            let total_len: u16 = (1 + NONCE_SIZE + ciphertext_len + SIGNATURE_SIZE) as u16;

            info!(
                target: "packet_builder",
                "Packet sizing - ciphertext_len: {}, total_len: {}",
                ciphertext_len, total_len
            );

            // Создаём выходной вектор
            let mut out = Vec::with_capacity(2 + 2 + total_len as usize);
            out.extend_from_slice(&HEADER_MAGIC);
            out.extend_from_slice(&total_len.to_be_bytes());
            out.push(packet_type_clone);

            // Определяем AAD для AES-GCM
            let aad_start = 0;
            let aad_end = out.len();
            let aad = &out[aad_start..aad_end];

            trace!(
                target: "packet_builder",
                "AAD range: {}-{}, AAD: {}",
                aad_start, aad_end, hex::encode(aad)
            );

            // Шифруем данные AES-GCM (используем клонированный контекст)
            let nonce = GenericArray::from_slice(&nonce_bytes);

            let encryption_start = std::time::Instant::now();
            let ciphertext = ctx_clone.aead_cipher.encrypt(
                nonce,
                Payload {
                    msg: &plaintext_clone, // используем клонированные данные
                    aad
                }
            ).expect("encryption failed");
            let encryption_duration = encryption_start.elapsed();

            info!(
                target: "packet_builder",
                "Encryption completed - duration: {:?}, ciphertext_len: {}",
                encryption_duration,
                ciphertext.len()
            );

            // Добавляем nonce и ciphertext
            out.extend_from_slice(&nonce_bytes);
            out.extend_from_slice(&ciphertext);

            // Вычисляем HMAC по всему пакету (используем клонированный контекст)
            let hmac_start = std::time::Instant::now();
            let mut mac = HmacSha256::new_from_slice(&ctx_clone.sign_key)
                .expect("bad hmac key");
            mac.update(&out);
            let tag = mac.finalize().into_bytes();
            let hmac_duration = hmac_start.elapsed();

            trace!(
                target: "packet_builder",
                "HMAC computed - duration: {:?}, tag: {}",
                hmac_duration,
                hex::encode(&tag)
            );

            out.extend_from_slice(&tag);

            let total_duration = thread_start.elapsed();
            let packet_size = out.len();

            info!(
                target: "packet_builder",
                "Packet build completed - total_duration: {:?}, packet_size: {}, breakdown: header={}, nonce={}, ciphertext={}, hmac={}",
                total_duration,
                packet_size,
                2 + 2 + 1, // HEADER_MAGIC + total_len + packet_type
                NONCE_SIZE,
                ciphertext.len(),
                SIGNATURE_SIZE
            );

            // Детальная разбивка пакета для отладки
            debug!(
                target: "packet_builder",
                "Packet structure - magic: {}, total_len: {}, type: 0x{:02X}, nonce: {}, ciphertext: {} bytes, hmac: {}",
                hex::encode(&HEADER_MAGIC),
                total_len,
                packet_type_clone,
                hex::encode(&nonce_bytes),
                ciphertext.len(),
                hex::encode(&tag)
            );

            out
        }).await.expect("encryption task failed");

        let total_duration = start_time.elapsed();

        info!(
            target: "packet_builder",
            "Encrypted packet build finished - total_async_duration: {:?}, packet_size: {}, type: 0x{:02X}, session_id: {}",
            total_duration,
            result.len(),
            packet_type,
            hex::encode(&ctx.session_id)
        );

        result
    }
}