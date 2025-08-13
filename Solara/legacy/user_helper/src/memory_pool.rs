// Memory Pool Allocation System for High-Performance ESP Data Processing
// Optimizes memory allocation for frequent ESP data updates in Rainbow Six Siege

use std::sync::Arc;
use tokio::sync::Mutex;
use std::collections::VecDeque;
use anyhow::Result;

/// Memory pool for efficient ESP data allocation
pub struct MemoryPool<T> {
    pool: Arc<Mutex<VecDeque<Box<T>>>>,
    max_size: usize,
    create_fn: Box<dyn Fn() -> T + Send + Sync>,
}

impl<T> MemoryPool<T> 
where 
    T: Default + Send + 'static,
{
    pub fn new(initial_size: usize, max_size: usize) -> Self {
        let mut pool = VecDeque::with_capacity(initial_size);
        
        // Pre-allocate objects
        for _ in 0..initial_size {
            pool.push_back(Box::new(T::default()));
        }
        
        Self {
            pool: Arc::new(Mutex::new(pool)),
            max_size,
            create_fn: Box::new(|| T::default()),
        }
    }
    
    pub fn with_factory<F>(initial_size: usize, max_size: usize, factory: F) -> Self 
    where 
        F: Fn() -> T + Send + Sync + 'static,
    {
        let mut pool = VecDeque::with_capacity(initial_size);
        
        // Pre-allocate objects using factory
        for _ in 0..initial_size {
            pool.push_back(Box::new(factory()));
        }
        
        Self {
            pool: Arc::new(Mutex::new(pool)),
            max_size,
            create_fn: Box::new(factory),
        }
    }
    
    /// Get an object from the pool (or create new if empty)
    pub async fn acquire(&self) -> PooledObject<T> {
        let mut pool = self.pool.lock().await;
        
        let obj = if let Some(obj) = pool.pop_front() {
            obj
        } else {
            // Pool is empty, create new object
            Box::new((self.create_fn)())
        };
        
        PooledObject {
            object: Some(obj),
            pool: Arc::clone(&self.pool),
            max_size: self.max_size,
        }
    }
    
    /// Get current pool size
    pub async fn size(&self) -> usize {
        self.pool.lock().await.len()
    }
    
    /// Clear the pool
    pub async fn clear(&self) {
        self.pool.lock().await.clear();
    }
}

/// RAII wrapper for pooled objects
pub struct PooledObject<T: Send + 'static> {
    object: Option<Box<T>>,
    pool: Arc<Mutex<VecDeque<Box<T>>>>,
    max_size: usize,
}

impl<T: Send + 'static> PooledObject<T> {
    /// Get mutable reference to the object
    pub fn get_mut(&mut self) -> &mut T {
        self.object.as_mut().unwrap().as_mut()
    }
    
    /// Get reference to the object
    pub fn get(&self) -> &T {
        self.object.as_ref().unwrap().as_ref()
    }
}

impl<T: Send + 'static> Drop for PooledObject<T> {
    fn drop(&mut self) {
        if let Some(obj) = self.object.take() {
            // Return object to pool (non-blocking)
            let pool = Arc::clone(&self.pool);
            let max_size = self.max_size;
            
            tokio::spawn(async move {
                let mut pool_guard = pool.lock().await;
                if pool_guard.len() < max_size {
                    pool_guard.push_back(obj);
                }
                // If pool is full, object is dropped
            });
        }
    }
}

/// Batch processor for ESP data updates
pub struct BatchProcessor<T> {
    batch: Vec<T>,
    batch_size: usize,
    processor: Box<dyn Fn(Vec<T>) -> Result<()> + Send + Sync>,
}

impl<T> BatchProcessor<T> 
where 
    T: Send + 'static,
{
    pub fn new<F>(batch_size: usize, processor: F) -> Self 
    where 
        F: Fn(Vec<T>) -> Result<()> + Send + Sync + 'static,
    {
        Self {
            batch: Vec::with_capacity(batch_size),
            batch_size,
            processor: Box::new(processor),
        }
    }
    
    /// Add item to batch, process if batch is full
    pub async fn add(&mut self, item: T) -> Result<()> {
        self.batch.push(item);
        
        if self.batch.len() >= self.batch_size {
            self.flush().await?;
        }
        
        Ok(())
    }
    
    /// Process current batch
    pub async fn flush(&mut self) -> Result<()> {
        if !self.batch.is_empty() {
            let batch = std::mem::take(&mut self.batch);
            (self.processor)(batch)?;
            self.batch.clear();
        }
        Ok(())
    }
    
    /// Get current batch size
    pub fn current_size(&self) -> usize {
        self.batch.len()
    }
}

/// Caching layer for offset validation results
pub struct ValidationCache {
    cache: Arc<Mutex<std::collections::HashMap<String, CacheEntry>>>,
    max_entries: usize,
    ttl: std::time::Duration,
}

#[derive(Clone)]
struct CacheEntry {
    value: bool,
    timestamp: std::time::Instant,
}

impl ValidationCache {
    pub fn new(max_entries: usize, ttl_seconds: u64) -> Self {
        Self {
            cache: Arc::new(Mutex::new(std::collections::HashMap::new())),
            max_entries,
            ttl: std::time::Duration::from_secs(ttl_seconds),
        }
    }
    
    /// Get cached validation result
    pub async fn get(&self, key: &str) -> Option<bool> {
        let mut cache = self.cache.lock().await;
        
        if let Some(entry) = cache.get(key) {
            if entry.timestamp.elapsed() < self.ttl {
                return Some(entry.value);
            } else {
                // Entry expired
                cache.remove(key);
            }
        }
        
        None
    }
    
    /// Store validation result
    pub async fn set(&self, key: String, value: bool) {
        let mut cache = self.cache.lock().await;
        
        // Remove oldest entries if cache is full
        if cache.len() >= self.max_entries {
            let oldest_key = cache
                .iter()
                .min_by_key(|(_, entry)| entry.timestamp)
                .map(|(k, _)| k.clone());
                
            if let Some(key) = oldest_key {
                cache.remove(&key);
            }
        }
        
        cache.insert(key, CacheEntry {
            value,
            timestamp: std::time::Instant::now(),
        });
    }
    
    /// Clear expired entries
    pub async fn cleanup_expired(&self) {
        let mut cache = self.cache.lock().await;
        let now = std::time::Instant::now();
        
        cache.retain(|_, entry| now.duration_since(entry.timestamp) < self.ttl);
    }
    
    /// Get cache statistics
    pub async fn stats(&self) -> (usize, usize) {
        let cache = self.cache.lock().await;
        let total = cache.len();
        let expired = cache
            .values()
            .filter(|entry| entry.timestamp.elapsed() >= self.ttl)
            .count();
            
        (total, expired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_memory_pool() {
        let pool = MemoryPool::<Vec<u8>>::new(2, 5);
        
        let mut obj1 = pool.acquire().await;
        obj1.get_mut().push(42);
        
        let mut obj2 = pool.acquire().await;
        obj2.get_mut().push(24);
        
        assert_eq!(pool.size().await, 0); // Both objects are in use
        
        drop(obj1);
        drop(obj2);
        
        // Give time for async drop to complete
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        assert_eq!(pool.size().await, 2); // Objects returned to pool
    }
    
    #[tokio::test]
    async fn test_validation_cache() {
        let cache = ValidationCache::new(10, 1);
        
        cache.set("test_key".to_string(), true).await;
        assert_eq!(cache.get("test_key").await, Some(true));
        
        // Test expiration
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        assert_eq!(cache.get("test_key").await, None);
    }
}
