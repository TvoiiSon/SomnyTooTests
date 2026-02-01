#[derive(Debug, Clone)]
pub struct BufferPoolConfig {
    pub initial_pool_size: usize,
    pub max_pool_size: usize,
    pub buffer_sizes: Vec<usize>,
    pub preallocate_percentage: f32,
}

impl Default for BufferPoolConfig {
    fn default() -> Self {
        Self {
            initial_pool_size: 100,
            max_pool_size: 1000,
            buffer_sizes: vec![
                64,      // Tiny packets
                256,     // Small packets
                1024,    // Medium packets
                4096,    // Large packets
                16384,   // Extra large
            ],
            preallocate_percentage: 0.3, // 30% preallocation
        }
    }
}