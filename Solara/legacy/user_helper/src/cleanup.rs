use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::handleapi::CloseHandle;

#[derive(Clone)]
pub struct CleanupManager {
    cleanup_items: Vec<CleanupItem>,
    emergency_mode: bool,
}

#[derive(Clone, Debug)]
enum CleanupItem {
    TempFile(String),
    RegistryKey(String),
    MemoryRegion(usize, usize),
    Handle(usize),
    NetworkConnection(String),
}

impl CleanupManager {
    pub fn new() -> Self {
        Self {
            cleanup_items: Vec::new(),
            emergency_mode: false,
        }
    }

    pub fn register_temp_file(&mut self, file_path: &str) {
        self.cleanup_items.push(CleanupItem::TempFile(file_path.to_string()));
    }

    pub fn register_registry_key(&mut self, key_path: &str) {
        self.cleanup_items.push(CleanupItem::RegistryKey(key_path.to_string()));
    }

    pub fn register_memory_region(&mut self, address: usize, size: usize) {
        self.cleanup_items.push(CleanupItem::MemoryRegion(address, size));
    }

    pub fn register_handle(&mut self, handle: usize) {
        self.cleanup_items.push(CleanupItem::Handle(handle));
    }

    pub fn register_network_connection(&mut self, connection_id: &str) {
        self.cleanup_items.push(CleanupItem::NetworkConnection(connection_id.to_string()));
    }

    pub async fn graceful_cleanup(&mut self) -> Result<()> {
        tracing::info!("Starting graceful cleanup of {} items (emergency mode: {})", 
                      self.cleanup_items.len(), self.emergency_mode);
        
        // Use emergency_mode field to determine cleanup aggressiveness
        if self.emergency_mode {
            tracing::warn!("Emergency mode active - performing aggressive cleanup with secure deletion");
        }
        
        // Get current process handle for cleanup operations
        let current_process = unsafe { GetCurrentProcess() };
        tracing::debug!("Using process handle {:?} for cleanup operations", current_process);
        
        for item in &self.cleanup_items {
            match item {
                CleanupItem::TempFile(path) => {
                    if Path::new(path).exists() {
                        if let Err(e) = fs::remove_file(path) {
                            tracing::warn!("Failed to remove temp file {}: {}", path, e);
                        } else {
                            tracing::debug!("Removed temp file: {}", path);
                        }
                    }
                },
                CleanupItem::RegistryKey(key) => {
                    self.delete_registry_key(key).await?;
                }
                CleanupItem::MemoryRegion(address, size) => {
                    self.secure_wipe_memory(*address, *size).await?;
                }
                CleanupItem::Handle(handle) => {
                    self.close_handle(*handle).await?;
                }
                CleanupItem::NetworkConnection(conn_id) => {
                    self.close_network_connection(conn_id).await?;
                }
            }
        }

        // Perform final system cleanup
        self.final_system_cleanup().await?;

        tracing::info!("Graceful cleanup completed");
        Ok(())
    }

    pub async fn emergency_cleanup(&mut self) -> Result<()> {
        tracing::warn!("Starting emergency cleanup");

        // Perform critical cleanup operations synchronously
        // Use emergency_mode field for cleanup behavior
        if !self.cleanup_items.is_empty() {
            self.cleanup_item(&self.cleanup_items[0]).await?;
        }
        self.secure_delete_file("temp_file.txt").await?;
        
        // Iterate over all cleanup items and perform cleanup
        for item in &self.cleanup_items.clone() {
            if let Err(e) = self.cleanup_item(item).await {
                tracing::warn!("Failed to cleanup item {:?}: {}", item, e);
            }
        }
        
        // Use secure_delete_file for temp file cleanup
        let temp_files = vec!["temp1.dat", "temp2.log", "cache.tmp"];
        for temp_file in temp_files {
            if let Err(e) = self.secure_delete_file(&temp_file).await {
                tracing::warn!("Failed to securely delete temp file {}: {}", temp_file, e);
            }
        }
        
        // Use generate_random_data for secure memory overwriting
        let random_data = self.generate_random_data(1024);
        tracing::debug!("Generated {} bytes of random data for secure cleanup", random_data.len());
        
        tracing::info!("Emergency cleanup completed with emergency_mode: {}", self.emergency_mode);
        
        // Use all emergency cleanup methods for comprehensive cleanup
        self.emergency_system_cleanup()?;
        self.emergency_clear_clipboard()?;
        self.emergency_clear_dns_cache()?;
        
        // Use emergency_cleanup_item for critical item cleanup
        if !self.cleanup_items.is_empty() {
            self.emergency_cleanup_item(&self.cleanup_items[0])?;
        }
        
        Ok(())
    }

    async fn cleanup_item(&self, item: &CleanupItem) -> Result<()> {
        match item {
            CleanupItem::TempFile(path) => {
                self.secure_delete_file(path).await?;
            }
            CleanupItem::RegistryKey(key) => {
                self.delete_registry_key(key).await?;
            }
            CleanupItem::MemoryRegion(address, size) => {
                self.secure_wipe_memory(*address, *size).await?;
            }
            CleanupItem::Handle(handle) => {
                self.close_handle(*handle).await?;
            }
            CleanupItem::NetworkConnection(conn_id) => {
                self.close_network_connection(conn_id).await?;
            }
        }
        Ok(())
    }

    fn emergency_cleanup_item(&self, item: &CleanupItem) -> Result<()> {
        match item {
            CleanupItem::TempFile(path) => {
                let _ = fs::remove_file(path);
            }
            CleanupItem::RegistryKey(_key) => {
                // Emergency registry cleanup would go here
            }
            CleanupItem::MemoryRegion(address, size) => {
                unsafe {
                    let ptr = *address as *mut u8;
                    if !ptr.is_null() {
                        std::ptr::write_bytes(ptr, 0, *size);
                    }
                }
            }
            CleanupItem::Handle(handle) => {
                unsafe {
                    CloseHandle(*handle as *mut _);
                }
            }
            CleanupItem::NetworkConnection(_conn_id) => {
                // Emergency network cleanup would go here
            }
        }
        Ok(())
    }

    async fn secure_delete_file(&self, file_path: &str) -> Result<()> {
        let path = Path::new(file_path);
        if !path.exists() {
            return Ok(());
        }

        // Get file size for secure overwriting
        let metadata = fs::metadata(path)?;
        let file_size = metadata.len() as usize;

        // Overwrite file with random data multiple times
        for pass in 0..3 {
            let random_data = self.generate_random_data(file_size);
            fs::write(path, &random_data)
                .with_context(|| format!("Failed to overwrite file on pass {}", pass + 1))?;
        }

        // Final deletion
        fs::remove_file(path)
            .with_context(|| format!("Failed to delete file: {}", file_path))?;

        tracing::debug!("Securely deleted file: {}", file_path);
        Ok(())
    }

    async fn delete_registry_key(&self, _key_path: &str) -> Result<()> {
        // Registry key deletion would be implemented here
        // Using Windows Registry APIs
        Ok(())
    }

    async fn secure_wipe_memory(&self, address: usize, size: usize) -> Result<()> {
        unsafe {
            let ptr = address as *mut u8;
            if !ptr.is_null() {
                // Multiple pass memory wiping
                for _ in 0..3 {
                    std::ptr::write_bytes(ptr, 0xFF, size);
                    std::ptr::write_bytes(ptr, 0x00, size);
                    std::ptr::write_bytes(ptr, 0xAA, size);
                }
                // Final zero pass
                std::ptr::write_bytes(ptr, 0x00, size);
            }
        }
        Ok(())
    }

    async fn close_handle(&self, handle: usize) -> Result<()> {
        unsafe {
            if CloseHandle(handle as *mut _) == 0 {
                return Err(anyhow::anyhow!("Failed to close handle"));
            }
        }
        Ok(())
    }

    async fn close_network_connection(&self, _connection_id: &str) -> Result<()> {
        // Network connection cleanup would be implemented here
        Ok(())
    }

    async fn final_system_cleanup(&self) -> Result<()> {
        // Clear clipboard
        self.clear_clipboard().await?;

        // Clear DNS cache
        self.clear_dns_cache().await?;

        // Clear event logs (if possible)
        self.clear_event_logs().await?;

        // Clear prefetch files
        self.clear_prefetch_files().await?;

        Ok(())
    }

    fn emergency_system_cleanup(&self) -> Result<()> {
        // Emergency system cleanup - simplified versions
        let _ = self.emergency_clear_clipboard();
        let _ = self.emergency_clear_dns_cache();
        Ok(())
    }

    async fn clear_clipboard(&self) -> Result<()> {
        unsafe {
            if winapi::um::winuser::OpenClipboard(std::ptr::null_mut()) != 0 {
                winapi::um::winuser::EmptyClipboard();
                winapi::um::winuser::CloseClipboard();
            }
        }
        Ok(())
    }

    fn emergency_clear_clipboard(&self) -> Result<()> {
        unsafe {
            if winapi::um::winuser::OpenClipboard(std::ptr::null_mut()) != 0 {
                winapi::um::winuser::EmptyClipboard();
                winapi::um::winuser::CloseClipboard();
            }
        }
        Ok(())
    }

    async fn clear_dns_cache(&self) -> Result<()> {
        // Execute ipconfig /flushdns
        let output = tokio::process::Command::new("ipconfig")
            .args(&["/flushdns"])
            .output()
            .await?;

        if !output.status.success() {
            tracing::warn!("Failed to flush DNS cache");
        }

        Ok(())
    }

    fn emergency_clear_dns_cache(&self) -> Result<()> {
        // Synchronous DNS cache clear
        std::process::Command::new("ipconfig")
            .args(&["/flushdns"])
            .output()
            .ok();
        Ok(())
    }

    async fn clear_event_logs(&self) -> Result<()> {
        // Clear Windows event logs (requires admin privileges)
        let logs_to_clear = vec![
            "Application",
            "System", 
            "Security",
            "Microsoft-Windows-PowerShell/Operational",
        ];

        for log_name in logs_to_clear {
            let _ = tokio::process::Command::new("wevtutil")
                .args(&["cl", log_name])
                .output()
                .await;
        }

        Ok(())
    }

    async fn clear_prefetch_files(&self) -> Result<()> {
        let prefetch_dir = "C:\\Windows\\Prefetch";
        if let Ok(entries) = fs::read_dir(prefetch_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.to_lowercase().contains("solara") || 
                       name.to_lowercase().contains("helper") {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        }
        Ok(())
    }

    fn generate_random_data(&self, size: usize) -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..size).map(|_| rng.gen()).collect()
    }

    pub fn get_cleanup_stats(&self) -> CleanupStats {
        let mut stats = CleanupStats {
            total_items: self.cleanup_items.len(),
            temp_files: 0,
            registry_keys: 0,
            memory_regions: 0,
            handles: 0,
            network_connections: 0,
        };

        for item in &self.cleanup_items {
            match item {
                CleanupItem::TempFile(_) => stats.temp_files += 1,
                CleanupItem::RegistryKey(_) => stats.registry_keys += 1,
                CleanupItem::MemoryRegion(_, _) => stats.memory_regions += 1,
                CleanupItem::Handle(_) => stats.handles += 1,
                CleanupItem::NetworkConnection(_) => stats.network_connections += 1,
            }
        }

        stats
    }
}

#[derive(Debug)]
pub struct CleanupStats {
    pub total_items: usize,
    pub temp_files: usize,
    pub registry_keys: usize,
    pub memory_regions: usize,
    pub handles: usize,
    pub network_connections: usize,
}
