pub mod config;
pub mod test_server;
pub mod test_client;

pub mod tests {
    pub mod send_ping_packet;
}

// CORE
pub mod core {
    pub mod protocol {
        pub mod error;
        pub mod crypto {
            pub mod crypto_pool_phantom;
        }
        pub mod phantom_crypto {
            pub mod packet;
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
            pub mod optimization {
                pub mod batch_processor;
                pub mod buffer_pool;
                pub mod packet_batch;
            }
            pub mod runtime {
                pub mod runtime;
            }
        }
        pub mod packets {
            pub mod decoder {
                pub mod frame_reader;
            }
            pub mod encoder {
                pub mod frame_writer;
            }
            pub mod processor {
                pub mod dispatcher;
                pub mod priority;
                pub mod packet_service;
                pub mod pipeline {
                    pub mod orchestrator;
                    pub mod stages {
                        pub mod common;
                        pub mod decryption;
                        pub mod encryption;
                        pub mod processing;
                    }
                }
            }
        }
        pub mod server {
            pub mod tcp_server_phantom;
            pub mod session_manager_phantom;
            pub mod connection_manager_phantom;
        }
    }
}
