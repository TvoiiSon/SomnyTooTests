pub mod config;
pub mod test_server;
pub mod test_client;

pub mod tests {
    pub mod send_ping_packet;
    pub mod test_benchmark;
}

// CORE
pub mod core {
    pub mod protocol {
        pub mod error;
        pub mod crypto {
            pub mod crypto_pool_phantom;
        }
        pub mod phantom_crypto {
            pub mod scatterer;
            pub mod runtime;
            pub mod packet;
            pub mod handshake;
            pub mod instance;
            pub mod assembler;
            pub mod keys;
        }
        pub mod packets {
            pub mod decoder {
                pub mod frame_reader;
                pub mod packet_parser_phantom;
            }
            pub mod encoder {
                pub mod frame_writer;
                pub mod packet_builder_phantom;
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
