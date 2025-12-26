pub mod config;

// CORE
pub mod core {
    pub mod handlers {

    }
    pub mod protocol {
        pub mod error;
        pub mod crypto {
            pub mod cipher {
                pub mod aes_gcm;
                pub mod key_derivation;
            }
            pub mod handshake {
                pub mod handshake;
            }
            pub mod key_manager {
                pub mod psk_manager;
                pub mod session_keys;
            }
            pub mod signature {
                pub mod hmac;
                pub mod verification;
            }
        }
        pub mod packets {
            pub mod decoder {
                pub mod frame_reader;
                pub mod packet_parser;
            }
            pub mod encoder {
                pub mod frame_writer;
                pub mod packet_builder;
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
                        pub mod response;
                    }
                }
            }
        }
        pub mod server {
            pub mod tcp_server;
            pub mod connection_manager;
            pub mod session_manager;
            pub mod client_packet_sender;
        }
    }
}
