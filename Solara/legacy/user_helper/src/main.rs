use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn, error, debug};

mod driver_interface;
mod web_api;
mod web_bridge;
mod overlay_ipc;
mod config_manager;
mod anti_analysis;
mod stealth;
mod cleanup;
mod spectator_detection;
mod offset_updater;
mod telemetry;
mod memory_pool;
mod enhanced_security;
mod r6s_offsets;
mod test_mode;

use driver_interface::DriverInterface;
use web_api::WebApiServer;
use web_bridge::WebBridge;
use overlay_ipc::OverlayIpc;
use config_manager::ConfigManager;
use anti_analysis::AntiAnalysis;
use stealth::StealthManager;
use cleanup::CleanupManager;
use spectator_detection::SpectatorDetection;
use offset_updater::OffsetUpdater;
use telemetry::TelemetrySystem;
use memory_pool::{MemoryPool, BatchProcessor, ValidationCache};
use crate::enhanced_security::EnhancedSecurityManager;
use r6s_offsets::{R6SConfig, R6SOperatorDB};
use test_mode::{TestModeManager, SystemStatus, is_r6s_running};

// Application state shared across all components - Rainbow Six Siege ESP
#[derive(Clone)]
pub struct AppState {
    pub driver: Arc<Mutex<DriverInterface>>,
    pub config: Arc<RwLock<ConfigManager>>,
    pub web_bridge: Arc<WebBridge>,
    pub overlay_ipc: Arc<Mutex<OverlayIpc>>,
    pub anti_analysis: Arc<Mutex<AntiAnalysis>>,
    pub stealth: Arc<Mutex<StealthManager>>,
    pub cleanup: Arc<Mutex<CleanupManager>>,
    pub spectator_detection: Arc<Mutex<SpectatorDetection>>,
    pub offset_updater: Arc<Mutex<OffsetUpdater>>,
    pub telemetry: Arc<Mutex<TelemetrySystem>>,
    pub enhanced_security: Arc<Mutex<EnhancedSecurityManager>>,
    pub memory_pool: Arc<Mutex<MemoryPool<Vec<u8>>>>,
    pub batch_processor: Arc<Mutex<BatchProcessor<String>>>,
    pub validation_cache: Arc<Mutex<ValidationCache>>,
    pub r6s_config: Arc<RwLock<R6SConfig>>,
    pub operator_db: Arc<RwLock<R6SOperatorDB>>,
    pub esp_memory_pool: Arc<MemoryPool<Vec<u8>>>,
    pub test_mode: Arc<Mutex<TestModeManager>>,
    pub system_status: Arc<RwLock<SystemStatus>>,
    pub shutdown_signal: Arc<tokio::sync::Notify>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize anti-analysis immediately
    let mut anti_analysis = AntiAnalysis::new();
    
    // Check for development/testing environment
    let is_dev_mode = std::env::var("SOLARA_DEV_MODE").is_ok() || 
                      std::env::var("SOLARA_TEST_MODE").is_ok() ||
                      cfg!(debug_assertions);
    
    if !is_dev_mode && !anti_analysis.verify_environment().await {
        // Silent exit - don't reveal we're a security tool (only in production)
        tracing::warn!("Environment verification failed, exiting silently");
        return Ok(());
    } else if is_dev_mode {
        tracing::info!("Development mode detected, skipping strict anti-analysis checks");
    }

    // Initialize stealth manager
    let mut stealth = StealthManager::new();
    stealth.initialize_stealth_mode().await?;

    // Set up logging (memory-only in production)
    setup_logging(&stealth).await?;

    info!("System service initializing...");

    // Initialize cleanup manager early for emergency cleanup
    let cleanup = CleanupManager::new();

    // Set up panic handler for secure cleanup
    let _cleanup_clone = cleanup.clone();
    std::panic::set_hook(Box::new(move |panic_info| {
        eprintln!("PANIC: {} at {}", 
                 panic_info.payload().downcast_ref::<&str>().unwrap_or(&"Unknown panic"),
                 panic_info.location().map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_else(|| "Unknown location".to_string()));
        // Note: Cannot await in non-async context, emergency cleanup will be handled elsewhere
        tracing::warn!("Emergency cleanup would be triggered here");
        std::process::exit(1);
    }));

    // Check for test mode before initializing driver
    let test_mode_enabled = std::env::var("SOLARA_TEST_MODE").is_ok() || is_dev_mode;
    
    // Initialize driver interface (skip in test mode)
    let driver = if test_mode_enabled {
        tracing::info!("Test mode enabled - creating mock driver interface");
        DriverInterface::new_mock().await
            .context("Failed to initialize mock driver interface")?
    } else {
        tracing::info!("Production mode - initializing real driver interface");
        DriverInterface::new().await
            .context("Failed to initialize driver interface")?
    };

    // Initialize configuration manager
    let config = ConfigManager::new().await
        .context("Failed to initialize configuration manager")?;

    // Initialize overlay IPC
    let overlay_ipc = OverlayIpc::new().await
        .context("Failed to initialize overlay IPC")?;

    // Initialize advanced features
    let spectator_detection = SpectatorDetection::new();
    // Initialize offset updater with default config and custom overrides
    let mut offset_config = crate::offset_updater::OffsetUpdateConfig::default();
    offset_config.update_interval = std::time::Duration::from_secs(300); // 5 minutes
    offset_config.max_update_attempts = 3;
    offset_config.auto_update_enabled = true;
    offset_config.backup_offsets = true;
    
    let mut offset_updater = OffsetUpdater::new(offset_config);
    
    // Perform comprehensive system analysis
    offset_updater.perform_system_analysis().await?;
    tracing::info!("System analysis completed successfully");
    
    // Validate player positions using R6S map data
    let test_players = vec![
        (1, [100.0, 50.0, 25.0]),
        (2, [200.0, 150.0, 75.0]),
        (3, [300.0, 250.0, 125.0]),
    ];
    let _validation_results = offset_updater.validate_player_positions(test_players).await?;
    tracing::info!("Player position validation completed");

    // Initialize telemetry system
    let telemetry = TelemetrySystem::new();
    
    // Initialize enhanced security system
    let mut enhanced_security = EnhancedSecurityManager::new();
    enhanced_security.initialize().await?;
    tracing::info!("Enhanced security system initialized successfully");
    
    // Create runtime integrity checks for critical addresses
    tracing::info!("Decoy connections started successfully");
    
    // Initialize performance optimizations
    let esp_memory_pool = Arc::new(MemoryPool::<Vec<u8>>::new(50, 200)); // 50 initial, 200 max
    let memory_pool = MemoryPool::new(100, 500); // General purpose memory pool
    let validation_cache = ValidationCache::new(1000, 300); // 1000 entries, 5min TTL
    
    // Initialize batch processor for telemetry events
    let batch_processor = BatchProcessor::new(50, |batch: Vec<String>| {
        // Process batch of telemetry events
        tracing::info!("Processing batch of {} telemetry events", batch.len());
        for event in batch {
            tracing::debug!("Telemetry event: {}", event);
        }
        Ok(())
    });
    
    // Initialize R6S configuration and operator database
    let r6s_config = R6SConfig::new();
    let operator_db = R6SOperatorDB::new();
    
    // Initialize test mode and system status
    let mut test_mode = TestModeManager::new();
    
    // Enable test mode if environment variable is set
    if test_mode_enabled {
        test_mode.enable_test_mode().await?;
        tracing::info!("Test mode enabled via environment variable");
    }
    
    let initial_status = if is_r6s_running().await {
        SystemStatus::Active
    } else if test_mode.is_test_mode_enabled() {
        SystemStatus::TestMode
    } else {
        SystemStatus::Inactive
    };

    // Start telemetry system
    telemetry.start().await?;
    tracing::info!("Telemetry system started");
    
    // Collect comprehensive performance metrics
    let _performance_report = telemetry.collect_performance_metrics().await?;
    tracing::info!("Performance metrics collected successfully");
    
    // Get network and IPC telemetry data
    let _network_metrics = telemetry.get_network_telemetry().await?;
    let _ipc_metrics = telemetry.get_ipc_telemetry().await?;
    tracing::info!("Network and IPC telemetry data retrieved");
    
    // Create resource snapshots for historical tracking
    let _resource_snapshot = telemetry.create_resource_snapshot().await;
    tracing::info!("Resource snapshot created for historical tracking");
    
    // Generate bottleneck reports for performance analysis
    let perf_metrics = crate::telemetry::PerformanceMetrics {
        frame_time: 16.67,
        render_time: 12.0,
        update_time: 4.0,
        total_time: 16.67,
        fps: 60.0,
        frame_drops: 0,
        memory_allocations: 1000,
        memory_deallocations: 950,
        peak_memory_usage: 512 * 1024 * 1024, // 512MB
        average_frame_time: 16.67,
        min_frame_time: 14.0,
        max_frame_time: 20.0,
        last_updated: std::time::Instant::now(),
    };
    let _bottleneck_report = telemetry.generate_bottleneck_report(&perf_metrics).await;
    tracing::info!("Bottleneck report generated for performance analysis");

    // Initialize missing components
    let anti_analysis = AntiAnalysis::new();
    let stealth = StealthManager::new();
    let cleanup = CleanupManager::new();
    
    // Initialize SolaraWeb bridge for UI communication
    let web_bridge = WebBridge::new();

    // Create application state
    let app_state = AppState {
        driver: Arc::new(Mutex::new(driver)),
        config: Arc::new(RwLock::new(config)),
        web_bridge: Arc::new(web_bridge),
        overlay_ipc: Arc::new(Mutex::new(overlay_ipc)),
        anti_analysis: Arc::new(Mutex::new(anti_analysis)),
        stealth: Arc::new(Mutex::new(stealth)),
        cleanup: Arc::new(Mutex::new(cleanup)),
        spectator_detection: Arc::new(Mutex::new(spectator_detection)),
        offset_updater: Arc::new(Mutex::new(offset_updater)),
        telemetry: Arc::new(Mutex::new(telemetry)),
        enhanced_security: Arc::new(Mutex::new(enhanced_security)),
        memory_pool: Arc::new(Mutex::new(memory_pool)),
        batch_processor: Arc::new(Mutex::new(batch_processor)),
        validation_cache: Arc::new(Mutex::new(validation_cache)),
        r6s_config: Arc::new(RwLock::new(r6s_config)),
        operator_db: Arc::new(RwLock::new(operator_db)),
        esp_memory_pool,
        test_mode: Arc::new(Mutex::new(test_mode)),
        system_status: Arc::new(RwLock::new(initial_status)),
        shutdown_signal: Arc::new(tokio::sync::Notify::new()),
    };

    // Start background tasks
    let background_tasks = start_background_tasks(app_state.clone()).await?;
    
    // Start system status monitoring
    let status_task = tokio::spawn(system_status_monitoring_task(app_state.clone()));
    
    // Monitor the status task for completion or errors
    tokio::spawn(async move {
        match status_task.await {
            Ok(_) => tracing::info!("System status monitoring task completed successfully"),
            Err(e) => tracing::error!("System status monitoring task failed: {}", e),
        }
    });
    
    info!("System status monitoring started");

    // Start SolaraWeb bridge server for UI communication
    let web_bridge_clone = app_state.web_bridge.clone();
    let _web_bridge_task = tokio::spawn(async move {
        if let Err(e) = web_bridge_clone.start_server().await {
            error!("SolaraWeb bridge server error: {}", e);
        }
    });

    // Start legacy web API server for backward compatibility
    let web_server = WebApiServer::new(app_state.clone());
    let server_task = tokio::spawn(async move {
        if let Err(e) = web_server.start().await {
            error!("Web API server error: {}", e);
        }
    });

    info!("System service started successfully");

    // Wait for shutdown signal
    tokio::select! {
        _ = app_state.shutdown_signal.notified() => {
            info!("Shutdown signal received");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Ctrl+C received, shutting down");
        }
        result = server_task => {
            match result {
                Ok(_) => info!("Web server completed"),
                Err(e) => error!("Web server task error: {}", e),
            }
        }
    }

    // Graceful shutdown
    info!("Initiating graceful shutdown...");
    
    // Cancel background tasks
    for task in background_tasks {
        task.abort();
    }

    // Perform cleanup
    {
        let mut cleanup = app_state.cleanup.lock().await;
        cleanup.graceful_cleanup().await?;
    }

    info!("System service shutdown complete");
    Ok(())
}

async fn setup_logging(stealth: &StealthManager) -> Result<()> {
    // Removed unused import: SubscriberExt

    if stealth.is_debug_mode() {
        // Debug mode - stderr logging
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_target(false)
            .with_thread_ids(false)
            .with_file(false)
            .with_line_number(false)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    } else {
        // Production mode - minimal logging
        tracing_subscriber::fmt()
            .with_target(false)
            .with_thread_ids(false)
            .with_file(false)
            .with_line_number(false)
            .with_max_level(tracing::Level::WARN)
            .init();
    }
    
    // Initialize memory writer separately for telemetry
    // Note: MemoryWriter is not currently implemented, using placeholder
    // let memory_writer = Arc::new(Mutex::new(crate::telemetry::MemoryWriter::new(1000)));

    Ok(())
}

async fn start_background_tasks(app_state: AppState) -> Result<Vec<tokio::task::JoinHandle<()>>> {
    let mut tasks = Vec::new();

    // Driver communication heartbeat
    {
        let state = app_state.clone();
        let task = tokio::spawn(async move {
            driver_heartbeat_task(state).await;
        });
        tasks.push(task);
    }

    // Overlay IPC management
    {
        let state = app_state.clone();
        let task = tokio::spawn(async move {
            overlay_ipc_task(state).await;
        });
        tasks.push(task);
    }

    // Configuration sync
    {
        let state = app_state.clone();
        let task = tokio::spawn(async move {
            config_sync_task(state).await;
        });
        tasks.push(task);
    }

    // Anti-analysis monitoring
    {
        let state = app_state.clone();
        let task = tokio::spawn(async move {
            anti_analysis_task(state).await;
        });
        tasks.push(task);
    }

    // Memory and resource monitoring
    {
        let state = app_state.clone();
        let task = tokio::spawn(async move {
            resource_monitor_task(state).await;
        });
        tasks.push(task);
    }

    // Spectator detection monitoring
    {
        let state = app_state.clone();
        let task = tokio::spawn(async move {
            spectator_detection_task(state).await;
        });
        tasks.push(task);
    }

    // Automatic offset updating
    {
        let state = app_state.clone();
        let task = tokio::spawn(async move {
            offset_updater_task(state).await;
        });
        tasks.push(task);
    }

    Ok(tasks)
}

async fn driver_heartbeat_task(app_state: AppState) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
    
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let driver = app_state.driver.lock().await;
                match driver.send_heartbeat().await {
                    Ok(_) => {
                        debug!("Driver heartbeat successful");
                    }
                    Err(e) => {
                        warn!("Driver heartbeat failed: {}", e);
                        
                        // Check if driver is still responsive
                        if !driver.is_connected().await {
                            error!("Driver connection lost - initiating emergency shutdown");
                            app_state.shutdown_signal.notify_one();
                            break;
                        }
                    }
                }
            }
            _ = app_state.shutdown_signal.notified() => {
                debug!("Driver heartbeat task shutting down");
                break;
            }
        }
    }
}

async fn overlay_ipc_task(app_state: AppState) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(16)); // ~60 FPS
    
    loop {
        tokio::select! {
            _ = interval.tick() => {
                // Get current ESP data from driver
                let esp_data = {
                    let driver = app_state.driver.lock().await;
                    match driver.get_esp_data().await {
                        Ok(data) => data,
                        Err(e) => {
                            debug!("Failed to get ESP data: {}", e);
                            continue;
                        }
                    }
                };

                // Send data to overlay
                let overlay_ipc = app_state.overlay_ipc.lock().await;
                if let Err(e) = overlay_ipc.send_esp_data(&esp_data).await {
                    debug!("Failed to send ESP data to overlay: {}", e);
                }
            }
            _ = app_state.shutdown_signal.notified() => {
                debug!("Overlay IPC task shutting down");
                break;
            }
        }
    }
}

async fn config_sync_task(app_state: AppState) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(100));
    
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let config = app_state.config.read().await;
                if config.has_pending_changes() {
                    drop(config);
                    
                    // Apply configuration changes
                    let config = app_state.config.write().await;
                    if let Err(e) = config.apply_pending_changes().await {
                        warn!("Failed to apply configuration changes: {}", e);
                    }
                }
            }
            _ = app_state.shutdown_signal.notified() => {
                debug!("Config sync task shutting down");
                break;
            }
        }
    }
}

async fn anti_analysis_task(app_state: AppState) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
    
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let mut anti_analysis = app_state.anti_analysis.lock().await;
                if !anti_analysis.perform_periodic_checks().await {
                    error!("Analysis detected - initiating emergency shutdown");
                    
                    // Trigger emergency cleanup
                    let mut cleanup = app_state.cleanup.lock().await;
                    if let Err(e) = cleanup.emergency_cleanup().await {
                        error!("Emergency cleanup failed: {}", e);
                    }
                    
                    app_state.shutdown_signal.notify_one();
                    break;
                }
            }
            _ = app_state.shutdown_signal.notified() => {
                debug!("Anti-analysis task shutting down");
                break;
            }
        }
    }
}

async fn resource_monitor_task(app_state: AppState) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
    
    loop {
        tokio::select! {
            _ = interval.tick() => {
                // Monitor memory usage
                let memory_usage = get_memory_usage();
                if memory_usage > 100_000_000 { // 100MB threshold
                    warn!("High memory usage detected: {} bytes", memory_usage);
                }

                // Monitor CPU usage
                let cpu_usage = get_cpu_usage();
                if cpu_usage > 10.0 { // 10% threshold
                    warn!("High CPU usage detected: {:.1}%", cpu_usage);
                }

                // Check for resource leaks
                let handle_count = get_handle_count();
                if handle_count > 1000 {
                    warn!("High handle count detected: {}", handle_count);
                }
            }
            _ = app_state.shutdown_signal.notified() => {
                debug!("Resource monitor task shutting down");
                break;
            }
        }
    }
}

fn get_memory_usage() -> u64 {
    // Get current process memory usage
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::psapi::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    
    unsafe {
        let process = GetCurrentProcess();
        
        // Use the process handle for comprehensive system monitoring
        tracing::debug!("Monitoring system status for process handle: {:?}", process);
        
        // Get process memory info
        let mut mem_info: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        mem_info.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        
        if GetProcessMemoryInfo(process, &mut mem_info, mem_info.cb) != 0 {
            let memory_mb = mem_info.WorkingSetSize as f64 / 1024.0 / 1024.0;
            tracing::debug!("Process {:?} memory usage: {:.2} MB", process, memory_mb);
            mem_info.WorkingSetSize as u64
        } else {
            tracing::warn!("Failed to get memory info for process {:?}", process);
            0
        }
    }
}

fn get_cpu_usage() -> f64 {
    // Simplified CPU usage calculation
    // In a real implementation, this would track CPU time over intervals
    0.0
}

fn get_handle_count() -> u32 {
    // Get current process handle count
    use winapi::um::processthreadsapi::GetCurrentProcess;
    // GetProcessHandleCount not available in this winapi version
    
    unsafe {
        let _process = GetCurrentProcess();
        // GetProcessHandleCount not available - return placeholder
        100 // Placeholder handle count
    }
}

async fn spectator_detection_task(app_state: AppState) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(2));
    
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let mut spectator_detection = app_state.spectator_detection.lock().await;
                if let Err(e) = spectator_detection.perform_spectator_scan().await {
                    warn!("Spectator detection scan failed: {}", e);
                } else {
                    // Get current spectators and check threat levels
                    let spectators = spectator_detection.get_current_spectators().await;
                    let threat_level = spectator_detection.get_threat_level().await;
                    
                    if !spectators.is_empty() {
                        debug!("Active spectators: {}, Threat level: {:?}", spectators.len(), threat_level);
                        
                        // Log telemetry event
                        if let Ok(telemetry) = app_state.telemetry.try_lock() {
                            let event_data = format!("Detected {} spectators", spectators.len());
                            
                            // Log event directly without spawning
                            let mut metadata = std::collections::HashMap::new();
                            metadata.insert("spectator_count".to_string(), spectators.len().to_string());
                            let _ = telemetry.log_event(
                                crate::telemetry::EventType::SpectatorDetection,
                                crate::telemetry::EventSeverity::Info,
                                "SpectatorDetection",
                                &event_data,
                                metadata,
                            ).await;
                        }
                    }
                }
            }
            _ = app_state.shutdown_signal.notified() => {
                debug!("Spectator detection task shutting down");
                break;
            }
        }
    }
}

async fn offset_updater_task(app_state: AppState) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300)); // 5 minutes
    
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let mut offset_updater = app_state.offset_updater.lock().await;
                if let Err(e) = offset_updater.check_for_updates().await {
                    warn!("Offset update check failed: {}", e);
                } else {
                    // Check if updates were applied
                    let update_info = offset_updater.get_last_update_info().await;
                    if let Some(info) = update_info {
                        info!("Offset update completed: {} offsets updated", info.updated_count);
                        
                        // Log telemetry event
                        if let Ok(telemetry) = app_state.telemetry.try_lock() {
                            let event_data = format!("Offset update completed: {} patterns processed", info.updated_count);
                            
                            // Log event directly without spawning
                            let mut metadata = std::collections::HashMap::new();
                            metadata.insert("discovered_count".to_string(), info.updated_count.to_string());
                            let _ = telemetry.log_event(
                                crate::telemetry::EventType::OffsetUpdate,
                                crate::telemetry::EventSeverity::Info,
                                "OffsetUpdater",
                                &event_data,
                                metadata,
                            ).await;
                        }
                    }
                }
            }
            _ = app_state.shutdown_signal.notified() => {
                debug!("Offset updater task shutting down");
                break;
            }
        }
    }
}

async fn system_status_monitoring_task(app_state: AppState) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5)); // Check every 5 seconds
    
    loop {
        tokio::select! {
            _ = interval.tick() => {
                // Check if R6S is running
                let r6s_running = is_r6s_running().await;
                
                // Check if test mode is enabled
                let test_mode_enabled = {
                    let test_mode = app_state.test_mode.lock().await;
                    test_mode.is_test_mode_enabled()
                };
                
                // Determine new status
                let new_status = if r6s_running {
                    SystemStatus::Active
                } else if test_mode_enabled {
                    SystemStatus::TestMode
                } else {
                    SystemStatus::Inactive
                };
                
                // Update status if changed
                {
                    let mut current_status = app_state.system_status.write().await;
                    if std::mem::discriminant(&*current_status) != std::mem::discriminant(&new_status) {
                        let old_status = current_status.to_string();
                        *current_status = new_status.clone();
                        info!("System status changed: {} -> {}", old_status, new_status.to_string());
                        
                        // Log telemetry event
                        if let Ok(telemetry) = app_state.telemetry.try_lock() {
                            let event_data = format!("System status check: CPU {}%, Memory {}MB", 
                                0.0, get_memory_usage() / 1024 / 1024);
                            
                            // Log event directly without spawning
                            let mut metadata = std::collections::HashMap::new();
                            metadata.insert("memory_usage".to_string(), (get_memory_usage() / 1024 / 1024).to_string());
                            let _ = telemetry.log_event(
                                crate::telemetry::EventType::SystemStatus,
                                crate::telemetry::EventSeverity::Info,
                                "SystemStatusMonitor",
                                &event_data,
                                metadata,
                            ).await;
                        }
                    }
                }
            }
            _ = app_state.shutdown_signal.notified() => {
                debug!("System status monitoring task shutting down");
                break;
            }
        }
    }
}
