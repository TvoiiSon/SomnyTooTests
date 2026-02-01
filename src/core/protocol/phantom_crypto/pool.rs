use std::sync::Arc;
use crate::core::protocol::phantom_crypto::core::instance::PhantomCrypto;

pub struct PhantomCryptoPool {
    crypto_instances: Vec<Arc<PhantomCrypto>>,
}

impl PhantomCryptoPool {
    pub fn new() -> Self {
        Self {
            crypto_instances: vec![Arc::new(PhantomCrypto::new())],
        }
    }

    pub fn get_instance(&self, index: usize) -> Option<Arc<PhantomCrypto>> {
        self.crypto_instances.get(index).cloned()
    }
}