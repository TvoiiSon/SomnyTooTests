use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, debug};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BufferType {
    Tiny,    // 64 bytes
    Small,   // 256 bytes
    Medium,  // 1024 bytes
    Large,   // 4096 bytes
    XLarge,  // 16384 bytes
    Custom(usize),
}

impl BufferType {
    pub fn size(&self) -> usize {
        match self {
            BufferType::Tiny => 64,
            BufferType::Small => 256,
            BufferType::Medium => 1024,
            BufferType::Large => 4096,
            BufferType::XLarge => 16384,
            BufferType::Custom(size) => *size,
        }
    }

    pub fn from_size(size: usize) -> Self {
        match size {
            0..=64 => BufferType::Tiny,
            65..=256 => BufferType::Small,
            257..=1024 => BufferType::Medium,
            1025..=4096 => BufferType::Large,
            4097..=16384 => BufferType::XLarge,
            _ => BufferType::Custom(size),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BufferStats {
    pub total_allocated: usize,
    pub total_reused: usize,
    pub current_allocated: usize,
    pub peak_allocated: usize,
    pub allocation_time_ns: u64,
    pub last_used: Instant,
}

impl Default for BufferStats {
    fn default() -> Self {
        Self {
            total_allocated: 0,
            total_reused: 0,
            current_allocated: 0,
            peak_allocated: 0,
            allocation_time_ns: 0,
            last_used: Instant::now(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GlobalBufferStats {
    pub total_memory_mb: f64,
    pub peak_memory_mb: f64,
    pub total_allocations: usize,
    pub total_reuses: usize,
    pub memory_pressure_alerts: usize,
    pub last_cleanup: Instant,
}

impl Default for GlobalBufferStats {
    fn default() -> Self {
        Self {
            total_memory_mb: 0.0,
            peak_memory_mb: 0.0,
            total_allocations: 0,
            total_reuses: 0,
            memory_pressure_alerts: 0,
            last_cleanup: Instant::now(),
        }
    }
}

pub struct BufferHandle {
    pub data: Vec<u8>,
    pub buffer_type: BufferType,
    pub allocated_at: Instant,
    pub last_used: Instant,
    pub allocation_time_ns: u64, // Добавляем поле
}

impl BufferHandle {
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
            buffer_type: BufferType::from_size(size),
            allocated_at: Instant::now(),
            last_used: Instant::now(),
            allocation_time_ns: 0, // Инициализируем
        }
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }

    pub fn reset(&mut self) {
        self.data.fill(0);
        self.last_used = Instant::now();
    }

    // Геттер для времени аллокации
    pub fn allocation_time_ns(&self) -> u64 {
        self.allocation_time_ns
    }

    // Сеттер для времени аллокации
    pub fn set_allocation_time_ns(&mut self, time_ns: u64) {
        self.allocation_time_ns = time_ns;
    }
}

#[derive(Debug, Clone)]
pub struct BufferPoolConfig {
    pub initial_pool_size: usize,
    pub max_pool_size: usize,
    pub buffer_sizes: Vec<usize>,
    pub preallocate_percentage: f32,
    pub cleanup_interval_secs: u64,
    pub max_buffer_age_secs: u64,
}

impl Default for BufferPoolConfig {
    fn default() -> Self {
        Self {
            initial_pool_size: 100,
            max_pool_size: 1000,
            buffer_sizes: vec![64, 256, 1024, 4096, 16384],
            preallocate_percentage: 0.3,
            cleanup_interval_secs: 60,
            max_buffer_age_secs: 300,
        }
    }
}

pub struct UnifiedBufferPool {
    pools: Arc<Mutex<HashMap<BufferType, Vec<BufferHandle>>>>,
    stats: Arc<Mutex<HashMap<BufferType, BufferStats>>>,
    global_stats: Arc<Mutex<GlobalBufferStats>>,
    config: BufferPoolConfig,
}

impl UnifiedBufferPool {
    pub fn new(config: BufferPoolConfig) -> Self {
        let pools = Arc::new(Mutex::new(HashMap::new()));
        let stats = Arc::new(Mutex::new(HashMap::new()));
        let global_stats = Arc::new(Mutex::new(GlobalBufferStats::default()));

        let pool = Self {
            pools: Arc::clone(&pools),
            stats: Arc::clone(&stats),
            global_stats: Arc::clone(&global_stats),
            config,
        };

        // Предварительное выделение буферов
        pool.preallocate_buffers();

        // Запускаем задачу очистки
        let pool_clone = pool.clone();
        tokio::spawn(async move {
            pool_clone.cleanup_task().await;
        });

        info!("🔄 UnifiedBufferPool initialized with {} buffer types",
              pool.config.buffer_sizes.len());

        pool
    }

    fn preallocate_buffers(&self) {
        let mut pools = self.pools.lock().unwrap();
        let mut stats = self.stats.lock().unwrap();
        let mut global_stats = self.global_stats.lock().unwrap();

        for &size in &self.config.buffer_sizes {
            let buffer_type = BufferType::from_size(size);
            let count = (self.config.initial_pool_size as f32 *
                self.config.preallocate_percentage) as usize;

            let mut buffer_list = Vec::with_capacity(count);
            for _ in 0..count {
                buffer_list.push(BufferHandle::new(size));
            }

            pools.insert(buffer_type, buffer_list);

            // Инициализируем статистику
            stats.insert(buffer_type, BufferStats::default());

            // Обновляем глобальную статистику
            global_stats.total_memory_mb += (size * count) as f64 / (1024.0 * 1024.0);
        }

        global_stats.peak_memory_mb = global_stats.total_memory_mb;
        global_stats.total_allocations = self.config.buffer_sizes.len();

        debug!("📊 Preallocated buffers: {:.2} MB", global_stats.total_memory_mb);
    }

    pub fn get_buffer(&self, size: usize) -> BufferHandle {
        let buffer_type = BufferType::from_size(size);
        let start_time = Instant::now();

        let mut pools = self.pools.lock().unwrap();
        let mut stats = self.stats.lock().unwrap();
        let mut global_stats = self.global_stats.lock().unwrap();

        // Пытаемся получить буфер из пула
        if let Some(buffer_list) = pools.get_mut(&buffer_type) {
            if let Some(mut buffer) = buffer_list.pop() {
                // Обновляем статистику
                if let Some(buffer_stats) = stats.get_mut(&buffer_type) {
                    buffer_stats.total_reused += 1;
                    buffer_stats.current_allocated += 1;
                    buffer_stats.last_used = Instant::now();

                    if buffer_stats.current_allocated > buffer_stats.peak_allocated {
                        buffer_stats.peak_allocated = buffer_stats.current_allocated;
                    }
                }

                global_stats.total_reuses += 1;

                buffer.reset();
                let allocation_time = start_time.elapsed().as_nanos() as u64;
                buffer.set_allocation_time_ns(allocation_time);

                debug!("🔄 Reused buffer of type {:?} ({} bytes) in {} ns",
                      buffer_type, buffer.size(), buffer.allocation_time_ns());

                return buffer;
            }
        }

        // Если буфера нет в пуле, создаем новый
        let mut buffer = BufferHandle::new(size);

        // Обновляем статистику
        if let Some(buffer_stats) = stats.get_mut(&buffer_type) {
            buffer_stats.total_allocated += 1;
            buffer_stats.current_allocated += 1;
            buffer_stats.last_used = Instant::now();

            if buffer_stats.current_allocated > buffer_stats.peak_allocated {
                buffer_stats.peak_allocated = buffer_stats.current_allocated;
            }
        } else {
            // Создаем новую статистику для этого типа
            let mut new_stats = BufferStats::default();
            new_stats.total_allocated = 1;
            new_stats.current_allocated = 1;
            new_stats.peak_allocated = 1;
            new_stats.last_used = Instant::now();
            stats.insert(buffer_type, new_stats);
        }

        global_stats.total_allocations += 1;
        global_stats.total_memory_mb += size as f64 / (1024.0 * 1024.0);

        if global_stats.total_memory_mb > global_stats.peak_memory_mb {
            global_stats.peak_memory_mb = global_stats.total_memory_mb;
        }

        let allocation_time = start_time.elapsed().as_nanos() as u64;
        buffer.set_allocation_time_ns(allocation_time);

        debug!("🆕 Allocated new buffer of type {:?} ({} bytes) in {} ns",
              buffer_type, buffer.size(), buffer.allocation_time_ns());

        buffer
    }

    pub fn return_buffer(&mut self, mut buffer: BufferHandle) {
        let buffer_type = buffer.buffer_type;

        let mut pools = self.pools.lock().unwrap();
        let mut stats = self.stats.lock().unwrap();

        // Проверяем, не превышен ли лимит пула
        if let Some(buffer_list) = pools.get_mut(&buffer_type) {
            if buffer_list.len() < self.config.max_pool_size {
                buffer.reset();
                buffer_list.push(buffer);

                // Обновляем статистику
                if let Some(buffer_stats) = stats.get_mut(&buffer_type) {
                    buffer_stats.current_allocated = buffer_stats.current_allocated.saturating_sub(1);
                }

                debug!("↩️ Returned buffer of type {:?} to pool", buffer_type);
            } else {
                // Пул переполнен, освобождаем буфер
                drop(buffer);
                debug!("🗑️ Pool full, discarded buffer of type {:?}", buffer_type);
            }
        } else {
            // Создаем новый список для этого типа
            let mut buffer_list = Vec::new();
            buffer.reset();
            buffer_list.push(buffer);
            pools.insert(buffer_type, buffer_list);

            debug!("📁 Created new pool for buffer type {:?}", buffer_type);
        }
    }

    pub fn cleanup_old_buffers(&self, max_age: Duration) {
        let mut pools = self.pools.lock().unwrap();
        let mut stats = self.stats.lock().unwrap();
        let mut global_stats = self.global_stats.lock().unwrap();

        let now = Instant::now();
        let mut total_cleaned = 0;
        let mut memory_freed_mb = 0.0;

        for (buffer_type, buffer_list) in pools.iter_mut() {
            let original_len = buffer_list.len();

            // Фильтруем старые буферы
            buffer_list.retain(|buffer| {
                let age = now.duration_since(buffer.last_used);
                age <= max_age
            });

            let cleaned = original_len - buffer_list.len();
            if cleaned > 0 {
                total_cleaned += cleaned;

                if let Some(buffer_stats) = stats.get_mut(buffer_type) {
                    buffer_stats.current_allocated = buffer_stats.current_allocated.saturating_sub(cleaned);
                }

                memory_freed_mb += (buffer_type.size() * cleaned) as f64 / (1024.0 * 1024.0);
            }
        }

        if total_cleaned > 0 {
            global_stats.total_memory_mb -= memory_freed_mb;
            global_stats.last_cleanup = now;

            debug!("🧹 Cleaned up {} old buffers, freed {:.2} MB",
                  total_cleaned, memory_freed_mb);
        }
    }

    async fn cleanup_task(&self) {
        let mut interval = tokio::time::interval(
            Duration::from_secs(self.config.cleanup_interval_secs)
        );

        loop {
            interval.tick().await;
            self.cleanup_old_buffers(Duration::from_secs(self.config.max_buffer_age_secs));
            self.log_pool_stats();
        }
    }

    pub fn log_pool_stats(&self) {
        let global_stats = self.global_stats.lock().unwrap();

        info!("📊 Buffer Pool Statistics:");
        info!("  Total memory: {:.2} MB", global_stats.total_memory_mb);
        info!("  Peak memory: {:.2} MB", global_stats.peak_memory_mb);
        info!("  Total allocations: {}", global_stats.total_allocations);
        info!("  Total reuses: {}", global_stats.total_reuses);
        info!("  Memory pressure alerts: {}", global_stats.memory_pressure_alerts);
    }

    pub fn clone(&self) -> Self {
        Self {
            pools: Arc::clone(&self.pools),
            stats: Arc::clone(&self.stats),
            global_stats: Arc::clone(&self.global_stats),
            config: self.config.clone(),
        }
    }
}