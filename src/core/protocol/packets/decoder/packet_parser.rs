use aes_gcm::{
    aead::{Aead, generic_array::GenericArray}
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use constant_time_eq::constant_time_eq;

use crate::core::protocol::crypto::key_manager::session_keys::SessionKeys;
use crate::core::protocol::error::{ProtocolError, CryptoError, ProtocolResult};

pub const HEADER_MAGIC: [u8; 2] = [0xAB, 0xCD];
const MAX_PAYLOAD_SIZE: usize = 1 << 20;
const SIGNATURE_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PacketType {
    Ping,
    Heartbeat,
    Unknown(u8),
}

impl From<u8> for PacketType {
    fn from(t: u8) -> Self {
        match t {
            0x01 => PacketType::Ping,
            0x10 => PacketType::Heartbeat,
            x => PacketType::Unknown(x),
        }
    }
}

#[derive(Debug, Clone)]
pub enum DecodeError {
    InvalidLength,
    InvalidMagic,
    InvalidSignature,
    DecryptionFailed,
    InvalidPacketType,
}

type HmacSha256 = Hmac<Sha256>;

pub struct PacketParser;

impl PacketParser {
    pub fn decode_packet(ctx: &SessionKeys, data: &[u8]) -> ProtocolResult<(u8, Vec<u8>)> {
        let minimal = 2 + 2 + 1 + NONCE_SIZE + 16 + SIGNATURE_SIZE;

        if data.len() < minimal {
            return Err(ProtocolError::MalformedPacket {
                details: format!("Packet too short: {} bytes", data.len())
            });
        }

        if !constant_time_eq(&data[0..2], &HEADER_MAGIC) {
            return Err(ProtocolError::MalformedPacket {
                details: "Invalid magic bytes".to_string()
            });
        }

        let length = u16::from_be_bytes([data[2], data[3]]) as usize;

        if length < 1 + NONCE_SIZE + 16 + SIGNATURE_SIZE {
            return Err(ProtocolError::MalformedPacket {
                details: "Invalid length field".to_string()
            });
        }

        if length > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::MalformedPacket {
                details: format!("Packet too large: {} bytes", length)
            });
        }

        let expected_total = 4 + length;
        if data.len() != expected_total {
            return Err(ProtocolError::MalformedPacket {
                details: format!("Length mismatch: expected {}, got {}", expected_total, data.len())
            });
        }

        let packet_type_raw = data[4];
        if packet_type_raw == 0xFF {
            return Err(ProtocolError::MalformedPacket {
                details: "Reserved packet type".to_string()
            });
        }

        let hmac_start = 4 + length - SIGNATURE_SIZE;
        if hmac_start <= 4 || hmac_start + SIGNATURE_SIZE > data.len() {
            return Err(ProtocolError::MalformedPacket {
                details: "Invalid HMAC position".to_string()
            });
        }

        let signed_part = &data[0..hmac_start];
        let signature = &data[hmac_start..hmac_start + SIGNATURE_SIZE];

        let mut mac = <HmacSha256 as Mac>::new_from_slice(&ctx.sign_key)
            .map_err(|_| ProtocolError::Crypto {
                source: CryptoError::InvalidKeyLength {
                    expected: 32,
                    actual: ctx.sign_key.len()
                }
            })?;

        mac.update(signed_part);

        let computed_tag = mac.finalize().into_bytes();
        if !constant_time_eq(&computed_tag, signature) {
            // ИСПРАВЛЕНИЕ: Сначала создаем ошибку, потом логируем
            let error = ProtocolError::Crypto {
                source: CryptoError::HmacVerificationFailed
            }.log();
            return Err(error);
        }

        let header_with_type_len = 2 + 2 + 1;
        if signed_part.len() < header_with_type_len + NONCE_SIZE + 16 {
            return Err(ProtocolError::MalformedPacket {
                details: "Invalid payload structure".to_string()
            });
        }

        let payload = &signed_part[header_with_type_len..];
        let nonce_bytes = &payload[..NONCE_SIZE];
        let ciphertext = &payload[NONCE_SIZE..];
        let aad = &signed_part[0..header_with_type_len];

        let nonce = GenericArray::from_slice(nonce_bytes);

        use aes_gcm::aead::Payload;
        let plaintext = ctx.aead_cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                }
            )
            .map_err(|e| ProtocolError::Crypto {
                source: CryptoError::DecryptionFailed {
                    reason: e.to_string()
                }
            })?;

        Ok((packet_type_raw, plaintext))
    }
}
