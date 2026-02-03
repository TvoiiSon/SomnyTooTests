pub mod config;

// CORE
pub mod core {
    pub mod protocol {
        pub mod error;
        pub mod phantom_crypto {
            pub mod packet;
            pub mod pool;
            pub mod core {
                pub mod instance;
                pub mod keys;
                pub mod handshake;
            }
            pub mod memory {
                pub mod scatterer;
                pub mod assembler;
            }
            pub mod acceleration {
                pub mod chacha20_accel;
                pub mod blake3_accel;
            }
            pub mod runtime {
                pub mod runtime;
            }
        }
        pub mod packets {
            pub mod packet_service;
            pub mod frame_reader;
            pub mod frame_writer;
        }
    }
}
pub mod tests {
    pub mod ping_test;
    pub mod test_utils;
}