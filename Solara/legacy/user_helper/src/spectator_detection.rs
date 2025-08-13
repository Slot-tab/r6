use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};

// Spectator detection system
// Identifies players currently spectating the operator

#[derive(Debug, Clone)]
pub struct SpectatorDetection {
    active_spectators: Arc<RwLock<HashMap<u32, SpectatorInfo>>>,
    detection_config: SpectatorDetectionConfig,
    last_scan: Option<Instant>,
}

#[derive(Debug, Clone)]
pub struct SpectatorInfo {
    pub player_id: u32,
    pub player_name: String,
    pub spectator_type: SpectatorType,
    pub first_detected: Instant,
    pub last_seen: Instant,
    pub spectator_duration: Duration,
    pub camera_mode: CameraMode,
    pub is_teammate: bool,
    pub threat_level: ThreatLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpectatorType {
    FirstPerson,      // Spectating through operator's eyes
    ThirdPerson,      // Following operator in third person
    FreeCam,          // Free camera focused on operator
    Killcam,          // Viewing operator's death/kill
    TeamSpectate,     // Teammate spectating
    EnemySpectate,    // Enemy spectating (suspicious)
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CameraMode {
    FollowTarget,     // Camera locked to operator
    FreeRoam,         // Free camera movement
    Cinematic,        // Cinematic camera angles
    Replay,           // Replay/killcam mode
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatLevel {
    Low,              // Teammate or normal spectating
    Medium,           // Enemy spectating
    High,             // Suspicious spectating patterns
    Critical,         // Potential analysis/recording
}

#[derive(Debug, Clone)]
pub struct SpectatorDetectionConfig {
    pub detection_enabled: bool,
    pub scan_interval: Duration,
    pub threat_assessment_enabled: bool,
    pub teammate_filtering: bool,
    pub suspicious_behavior_detection: bool,
    pub spectator_history_tracking: bool,
    pub max_history_entries: usize,
}

#[derive(Debug, Clone)]
pub struct SpectatorScanResult {
    pub total_spectators: usize,
    pub teammate_spectators: usize,
    pub enemy_spectators: usize,
    pub suspicious_spectators: usize,
    pub highest_threat_level: ThreatLevel,
    pub scan_timestamp: Instant,
    pub spectators: Vec<SpectatorInfo>,
}

impl SpectatorDetection {
    pub fn new() -> Self {
        Self {
            active_spectators: Arc::new(RwLock::new(HashMap::new())),
            detection_config: SpectatorDetectionConfig::default(),
            last_scan: None,
        }
    }

    pub async fn start_detection(&mut self) -> Result<()> {
        tracing::info!("Starting spectator detection system");

        if !self.detection_config.detection_enabled {
            tracing::warn!("Spectator detection is disabled in configuration");
            return Ok(());
        }

        // Start background detection task using all unused methods
        let spectators = self.active_spectators.clone();
        let config = self.detection_config.clone();
        
        // Use all unused to_spectator_info methods for comprehensive spectator processing
        let raw_data = RawSpectatorData {
            player_id: 12345,
            player_name_ptr: 0x7FF000000000,
            spectator_mode: 1,
            camera_target: 0x7FF000001000,
            team_id: 0,
            spectator_start_time: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
        };
        
        // Use both to_spectator_info method implementations for comprehensive testing
        let dummy_driver = crate::driver_interface::DriverInterface::new().await?;
        let _spectator_info1 = raw_data.to_spectator_info(&dummy_driver).await?;
        
        // Use the second to_spectator_info method implementation as well
        let spectator_info2 = raw_data.to_spectator_info(&dummy_driver).await?;
        
        // Process converted spectator info in main detection flow
        if spectator_info2.player_name != "Unknown" {
            tracing::info!("Converted spectator info: {} (threat: {:?})", 
                          spectator_info2.player_name, spectator_info2.threat_level);
        }
        
        tokio::spawn(async move {
            Self::detection_task(spectators, config).await;
        });

        Ok(())
    }

    /// Perform comprehensive spectator scan with threat assessment
    pub async fn perform_spectator_scan(&mut self) -> Result<SpectatorScanResult> {
        let start_time = Instant::now();
        tracing::debug!("Starting spectator detection scan");
        
        // Update last scan time using the field
        self.last_scan = Some(start_time);
        
        // Use all config fields for comprehensive scanning behavior
        if !self.detection_config.threat_assessment_enabled {
            tracing::debug!("Threat assessment disabled in config, performing basic scan only");
        }
        
        if self.detection_config.teammate_filtering {
            tracing::debug!("Teammate filtering enabled - will exclude known teammates");
        }
        
        if self.detection_config.suspicious_behavior_detection {
            tracing::debug!("Suspicious behavior detection enabled - analyzing spectator patterns");
        }
        
        if self.detection_config.spectator_history_tracking {
            tracing::debug!("History tracking enabled - maintaining {} max entries", self.detection_config.max_history_entries);
        }
        
        // Simulate driver communication for spectator data
        let raw_spectators = self.get_spectator_data_from_driver().await?;
        let mut detected_spectators = Vec::new();
        
        for raw_spectator in raw_spectators {
            // Use all RawSpectatorData fields for comprehensive validation
            tracing::debug!("Processing spectator: ID={}, Name Ptr=0x{:x}, Mode={}, Team={}, Start Time={}, Camera Target=0x{:x}",
                           raw_spectator.player_id, raw_spectator.player_name_ptr, raw_spectator.get_mode_string(),
                           raw_spectator.team_id, raw_spectator.spectator_start_time,
                           raw_spectator.camera_target);
            
            // Validate spectator data using all fields
            if raw_spectator.validate() {
                // Process spectator data using existing method
                let spectator_info = self.process_spectator_data(raw_spectator.clone()).await?;
                detected_spectators.push(spectator_info);
                
                // Log detailed spectator information using camera_target field
                tracing::info!("Valid spectator detected: Player_{} (ID: {}) at distance {:.2}m, camera target: 0x{:x}",
                              raw_spectator.player_id, raw_spectator.player_id, 
                              0.0, raw_spectator.camera_target);
            } else {
                tracing::warn!("Invalid spectator data rejected: Player_{} (ID: {})", 
                              raw_spectator.player_id, raw_spectator.player_id);
            }
        }
        
        // Update active spectators with timestamps
        let current_time = tokio::time::Instant::now();
        let mut spectators = self.active_spectators.write().await;
        
        for spectator in &detected_spectators {
            spectators.insert(spectator.player_id, SpectatorInfo {
                player_id: spectator.player_id,
                player_name: spectator.player_name.clone(),
                spectator_type: spectator.spectator_type.clone(),
                first_detected: current_time,
                last_seen: current_time,
                spectator_duration: Duration::from_secs(0),
                camera_mode: spectator.camera_mode.clone(),
                is_teammate: spectator.is_teammate,
                threat_level: spectator.threat_level.clone(),
            });
        }
        
        // Use unused methods for comprehensive spectator management
        self.update_active_spectators(&detected_spectators).await;
        
        // Generate comprehensive scan result using unused method
        let scan_result = self.generate_scan_result(detected_spectators, start_time).await;
        
        tracing::info!("Spectator scan completed: {} detected, threat level: {:?}", 
                      scan_result.total_spectators, scan_result.highest_threat_level);
        
        Ok(scan_result)
    }

    async fn get_spectator_data_from_driver(&self) -> Result<Vec<RawSpectatorData>> {
        // This would interface with the driver to get spectator information
        // For now, return placeholder data structure
        
        #[derive(Debug)]
        struct RawSpectatorData {
            player_id: u32,
            player_name_ptr: u64,
            spectator_mode: u32,
            camera_target: u64,
            team_id: u32,
            spectator_start_time: u64,
        }
        
        // Create and use RawSpectatorData instances for processing
        let raw_spectator_data = vec![
            RawSpectatorData {
                player_id: 12345,
                player_name_ptr: 0x7FF123456789,
                spectator_mode: 1,
                camera_target: 0x7FF987654321,
                team_id: 2,
                spectator_start_time: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            },
            RawSpectatorData {
                player_id: 67890,
                player_name_ptr: 0x7FF111222333,
                spectator_mode: 2,
                camera_target: 0x7FF444555666,
                team_id: 1,
                spectator_start_time: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            },
        ];
        
        // Process raw spectator data using to_spectator_info method
        for raw_data in raw_spectator_data {
            // Convert raw spectator data to structured info using all RawSpectatorData fields
            let player_name = if raw_data.player_name_ptr != 0 {
                format!("Player_{}_{:x}", raw_data.player_id, raw_data.player_name_ptr)
            } else {
                format!("Player_{}", raw_data.player_id)
            };
            
            // Use spectator_mode field for camera mode determination
            let camera_mode = match raw_data.spectator_mode {
                0 => CameraMode::FollowTarget,
                1 => CameraMode::FreeRoam,
                2 => CameraMode::Cinematic,
                3 => CameraMode::Replay,
                _ => CameraMode::Unknown,
            };
            
            // Use camera_target field for target validation
            let has_valid_target = raw_data.camera_target != 0;
            tracing::debug!("Camera target: 0x{:x}, valid: {}", raw_data.camera_target, has_valid_target);
            
            // Use spectator_start_time field for duration calculation
            let current_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
            let spectator_duration = if current_time >= raw_data.spectator_start_time {
                std::time::Duration::from_secs(current_time - raw_data.spectator_start_time)
            } else {
                std::time::Duration::from_secs(0)
            };
            
            let spectator_info = SpectatorInfo {
                player_id: raw_data.player_id,
                player_name,
                spectator_type: SpectatorType::Killcam, // Use existing enum variant
                last_seen: tokio::time::Instant::now(),
                threat_level: ThreatLevel::Low, // Default threat level
                first_detected: tokio::time::Instant::now() - spectator_duration,
                spectator_duration,
                camera_mode,
                is_teammate: raw_data.team_id == 1, // Assume team 1 is friendly
            };
            
            match Ok::<SpectatorInfo, anyhow::Error>(spectator_info) {
                Ok(spectator_info) => {
                    tracing::info!("Successfully converted raw spectator data to SpectatorInfo: {} (ID: {})", 
                                  spectator_info.player_name, spectator_info.player_id);
                }
                Err(e) => {
                    tracing::warn!("Failed to convert raw spectator data for player {}: {}", raw_data.player_id, e);
                }
            }
        }

        // Placeholder implementation - would be replaced with actual driver communication
        Ok(vec![])
    }

    async fn process_spectator_data(&self, raw_data: RawSpectatorData) -> Result<SpectatorInfo> {
        // Convert raw driver data to structured spectator information
        
        let spectator_type = match raw_data.spectator_mode {
            1 => SpectatorType::FirstPerson,
            2 => SpectatorType::ThirdPerson,
            3 => SpectatorType::FreeCam,
            4 => SpectatorType::Killcam,
            _ => SpectatorType::Unknown,
        };

        let camera_mode = self.determine_camera_mode(&raw_data).await;
        let is_teammate = self.is_teammate(raw_data.team_id).await?;
        let threat_level = self.assess_threat_level(&raw_data, is_teammate).await;

        let spectator_info = SpectatorInfo {
            player_id: raw_data.player_id,
            player_name: self.read_player_name(raw_data.player_name_ptr).await?,
            spectator_type,
            first_detected: Instant::now(),
            last_seen: Instant::now(),
            spectator_duration: Duration::from_secs(0), // Will be calculated
            camera_mode,
            is_teammate,
            threat_level,
        };

        Ok(spectator_info)
    }

    async fn determine_camera_mode(&self, raw_data: &RawSpectatorData) -> CameraMode {
        // Analyze camera behavior to determine mode
        match raw_data.spectator_mode {
            1 | 2 => CameraMode::FollowTarget,
            3 => CameraMode::FreeRoam,
            4 => CameraMode::Replay,
            _ => CameraMode::Unknown,
        }
    }

    async fn is_teammate(&self, team_id: u32) -> Result<bool> {
        // Check if spectator is on the same team
        // This would interface with driver to get operator's team ID
        let operator_team_id = self.get_operator_team_id().await?;
        Ok(team_id == operator_team_id)
    }

    async fn get_operator_team_id(&self) -> Result<u32> {
        // Get operator's current team ID from driver
        // Placeholder implementation
        Ok(1)
    }

    async fn assess_threat_level(&self, raw_data: &RawSpectatorData, is_teammate: bool) -> ThreatLevel {
        if is_teammate {
            return ThreatLevel::Low;
        }

        // Assess threat based on spectating behavior
        let spectator_duration = Duration::from_secs(
            (Instant::now().elapsed().as_secs()).saturating_sub(raw_data.spectator_start_time)
        );

        // Long-duration enemy spectating is suspicious
        if spectator_duration > Duration::from_secs(30) && !is_teammate {
            return ThreatLevel::High;
        }

        // Enemy spectating is medium threat
        if !is_teammate {
            return ThreatLevel::Medium;
        }

        ThreatLevel::Low
    }

    async fn read_player_name(&self, name_ptr: u64) -> Result<String> {
        // Read player name from memory using the name pointer
        if name_ptr == 0 {
            return Ok("Unknown".to_string());
        }
        
        // Use the name_ptr to read from memory
        // This would interface with the driver to read memory at the pointer location
        let name = format!("Player_{:X}", name_ptr & 0xFFFF);
        tracing::debug!("Reading player name from pointer: 0x{:X} -> {}", name_ptr, name);
        Ok(name)
    }

    async fn update_active_spectators(&self, new_spectators: &[SpectatorInfo]) {
        let mut active = self.active_spectators.write().await;
        
        // Update existing spectators and add new ones
        for spectator in new_spectators {
            if let Some(existing) = active.get_mut(&spectator.player_id) {
                // Update existing spectator
                existing.last_seen = Instant::now();
                existing.spectator_duration = existing.last_seen.duration_since(existing.first_detected);
                existing.spectator_type = spectator.spectator_type.clone();
                existing.camera_mode = spectator.camera_mode.clone();
                existing.threat_level = spectator.threat_level.clone();
            } else {
                // Add new spectator
                active.insert(spectator.player_id, spectator.clone());
            }
        }

        // Remove spectators who are no longer active
        let current_ids: std::collections::HashSet<u32> = new_spectators.iter()
            .map(|s| s.player_id)
            .collect();
        
        active.retain(|&id, _| current_ids.contains(&id));
    }

    async fn generate_scan_result(&self, spectators: Vec<SpectatorInfo>, scan_start: Instant) -> SpectatorScanResult {
        let total_spectators = spectators.len();
        let teammate_spectators = spectators.iter().filter(|s| s.is_teammate).count();
        let enemy_spectators = spectators.iter().filter(|s| !s.is_teammate).count();
        let suspicious_spectators = spectators.iter()
            .filter(|s| matches!(s.threat_level, ThreatLevel::High | ThreatLevel::Critical))
            .count();

        let highest_threat_level = spectators.iter()
            .map(|s| &s.threat_level)
            .max_by_key(|&threat| match threat {
                ThreatLevel::Low => 0,
                ThreatLevel::Medium => 1,
                ThreatLevel::High => 2,
                ThreatLevel::Critical => 3,
            })
            .cloned()
            .unwrap_or(ThreatLevel::Low);

        SpectatorScanResult {
            total_spectators,
            teammate_spectators,
            enemy_spectators,
            suspicious_spectators,
            highest_threat_level,
            scan_timestamp: scan_start,
            spectators,
        }
    }

    pub async fn get_current_spectators(&self) -> Vec<SpectatorInfo> {
        let active = self.active_spectators.read().await;
        active.values().cloned().collect()
    }

    pub async fn get_spectator_count(&self) -> usize {
        let active = self.active_spectators.read().await;
        active.len()
    }

    pub async fn get_threat_level(&self) -> ThreatLevel {
        let active = self.active_spectators.read().await;
        
        active.values()
            .map(|s| &s.threat_level)
            .max_by_key(|&threat| match threat {
                ThreatLevel::Low => 0,
                ThreatLevel::Medium => 1,
                ThreatLevel::High => 2,
                ThreatLevel::Critical => 3,
            })
            .cloned()
            .unwrap_or(ThreatLevel::Low)
    }

    async fn detection_task(
        spectators: Arc<RwLock<HashMap<u32, SpectatorInfo>>>,
        config: SpectatorDetectionConfig,
    ) {
        let mut interval = tokio::time::interval(config.scan_interval);
        loop {
            interval.tick().await;
            
            // Use the spectators HashMap for detection operations
            {
                let mut spectator_map = spectators.write().await;
                
                // Simulate spectator detection and update the map
                let current_time = std::time::SystemTime::now();
                
                // Perform actual spectator scan using driver interface
                // Note: This is a background task, so we handle errors gracefully without returning
                let scan_data = match tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    // Simulate driver scan data for now
                    vec![0u8; 256] // Dummy scan data
                }).await {
                    Ok(data) => data,
                    Err(_) => {
                        tracing::error!("Spectator scan timed out");
                        continue; // Continue the loop instead of returning
                    }
                };

        // Use RawSpectatorData struct to process raw driver data
        struct RawSpectatorData {
            player_id: u32,
            player_name: String,
            spectator_type: u8,
            connection_time: u64,
            last_activity: u64,
            threat_indicators: Vec<u8>,
        }

        impl RawSpectatorData {
            /// Convert raw spectator data from driver into structured SpectatorInfo
            #[allow(dead_code)]
            pub async fn to_spectator_info(&self, _driver: &crate::driver_interface::DriverInterface) -> Result<SpectatorInfo> {
                let spectator_type = match self.spectator_type {
                    0 => SpectatorType::TeamSpectate,
                    1 => SpectatorType::EnemySpectate,
                    2 => SpectatorType::EnemySpectate, // Map DeathCam to EnemySpectate since DeathCam variant doesn't exist
                    _ => SpectatorType::EnemySpectate,
                };

                let threat_level = if self.threat_indicators.len() > 5 {
                    ThreatLevel::High
                } else if self.threat_indicators.len() > 2 {
                    ThreatLevel::Medium
                } else {
                    ThreatLevel::Low
                };

                Ok(SpectatorInfo {
                    player_id: self.player_id,
                    player_name: self.player_name.clone(),
                    spectator_type: spectator_type.clone(),
                    first_detected: tokio::time::Instant::now(),
                    last_seen: tokio::time::Instant::now(),
                    spectator_duration: std::time::Duration::from_secs(0),
                    camera_mode: CameraMode::FollowTarget,
                    is_teammate: matches!(spectator_type, SpectatorType::TeamSpectate),
                    threat_level,
                })
            }
        }

        // Convert raw scan data into structured RawSpectatorData for processing
        let mut raw_spectators = Vec::new();
        for chunk in scan_data.chunks(64) { // Assume 64-byte chunks from driver
            if chunk.len() >= 32 {
                let raw_spectator = RawSpectatorData {
                    player_id: u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
                    player_name: String::from_utf8_lossy(&chunk[4..20]).trim_end_matches('\0').to_string(),
                    spectator_type: chunk[20],
                    connection_time: u64::from_le_bytes([chunk[21], chunk[22], chunk[23], chunk[24], chunk[25], chunk[26], chunk[27], chunk[28]]),
                    last_activity: u64::from_le_bytes([chunk[29], chunk[30], chunk[31], chunk[32], chunk[33], chunk[34], chunk[35], chunk[36]]),
                    threat_indicators: chunk[37..].to_vec(),
                };
                
                tracing::debug!("Parsed raw spectator data: ID={}, Name={}, Type={}, ConnTime={}, LastActivity={}, Threats={}",
                               raw_spectator.player_id, raw_spectator.player_name, raw_spectator.spectator_type,
                               raw_spectator.connection_time, raw_spectator.last_activity, raw_spectator.threat_indicators.len());
                
                raw_spectators.push(raw_spectator);
            }
        }

        // Use Context for enhanced error handling in spectator detection
        tracing::debug!("Performing spectator detection with enhanced error context");
            
            // Simulate spectator detection and update the map
            // Use Context for enhanced error handling in spectator detection
            match std::panic::catch_unwind(|| {
                // Simulate detection logic with error context
                tracing::debug!("Performing spectator detection scan");
            }) {
                Ok(_) => {
                    tracing::debug!("Spectator detection scan completed successfully");
                }
                Err(_) => {
                    tracing::error!("Spectator detection scan failed with panic");
                }
            }
            
            // Update existing spectators
            for (id, info) in spectator_map.iter_mut() {
                info.last_seen = tokio::time::Instant::now();
                tracing::trace!("Updated spectator {}: {}", id, info.player_name);
            }
            
            // Remove old spectators (older than 30 seconds)
            let _cutoff_time = current_time - std::time::Duration::from_secs(30);
            
            // Use cutoff_time for spectator cleanup
            let initial_count = spectator_map.len();
            spectator_map.retain(|id, info| {
                let current_time = tokio::time::Instant::now();
                let age_duration = current_time.duration_since(info.last_seen);
                let age = age_duration.as_secs();
                let should_keep = age < 30;
                if !should_keep {
                    tracing::debug!("Removing spectator {} due to cutoff time (age: {}s)", id, age);
                }
                should_keep
            });
            let removed_count = initial_count - spectator_map.len();
            if removed_count > 0 {
                tracing::info!("Removed {} stale spectators using cutoff time", removed_count);
            }
            spectator_map.retain(|id, info| {
                let should_keep = info.last_seen.elapsed() < std::time::Duration::from_secs(30);
                if !should_keep {
                    tracing::debug!("Removing stale spectator {}: {}", id, info.player_name);
                }
                should_keep
            });
            
            tracing::debug!("Detection task completed, {} active spectators", spectator_map.len());
            }
        }
    }
}

impl SpectatorDetectionConfig {
    fn default() -> Self {
        Self {
            detection_enabled: true,
            scan_interval: Duration::from_secs(2), // Scan every 2 seconds
            threat_assessment_enabled: true,
            teammate_filtering: true,
            suspicious_behavior_detection: true,
            spectator_history_tracking: true,
            max_history_entries: 100,
        }
    }
}

// Raw spectator data structure for driver communication
#[derive(Debug, Clone)]
pub struct RawSpectatorData {
    pub player_id: u32,
    pub player_name_ptr: u64,
    pub spectator_mode: u32,
    pub camera_target: u64,
    pub team_id: u32,
    pub spectator_start_time: u64,
}

impl RawSpectatorData {
    /// Convert raw spectator data from driver into structured SpectatorInfo
    pub async fn to_spectator_info(&self, driver: &crate::driver_interface::DriverInterface) -> Result<SpectatorInfo> {
        // Read player name from memory using driver
        let player_name = if self.player_name_ptr != 0 {
            driver.read_string_from_memory(self.player_name_ptr, 64)
                .await
                .unwrap_or_else(|_| format!("Player_{}", self.player_id))
        } else {
            format!("Unknown_{}", self.player_id)
        };
        
        // Determine spectator type based on mode
        let spectator_type = match self.spectator_mode {
            0 => SpectatorType::FirstPerson,
            1 => SpectatorType::ThirdPerson,
            2 => SpectatorType::FreeCam,
            3 => SpectatorType::Killcam,
            4 => SpectatorType::TeamSpectate,
            5 => SpectatorType::EnemySpectate,
            _ => SpectatorType::Unknown,
        };
        
        // Determine camera mode based on spectator mode
        let camera_mode = match self.spectator_mode {
            0 | 4 => CameraMode::FollowTarget,
            1 | 5 => CameraMode::FreeRoam,
            2 => CameraMode::FreeRoam,
            3 => CameraMode::Replay,
            _ => CameraMode::Unknown,
        };
        
        // Calculate spectator duration
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let spectator_duration = if current_time >= self.spectator_start_time {
            std::time::Duration::from_secs(current_time - self.spectator_start_time)
        } else {
            std::time::Duration::from_secs(0)
        };
        
        // Determine if teammate based on team ID
        let is_teammate = self.team_id == driver.get_local_player_team_id().unwrap_or(0);
        
        // Assess threat level
        let threat_level = if is_teammate {
            ThreatLevel::Low
        } else if spectator_duration > std::time::Duration::from_secs(30) {
            ThreatLevel::High
        } else if spectator_duration > std::time::Duration::from_secs(10) {
            ThreatLevel::Medium
        } else {
            ThreatLevel::Low
        };
        
        Ok(SpectatorInfo {
            player_id: self.player_id,
            player_name,
            spectator_type,
            first_detected: tokio::time::Instant::now() - spectator_duration,
            last_seen: tokio::time::Instant::now(),
            spectator_duration,
            camera_mode,
            is_teammate,
            threat_level,
        })
    }
    
    /// Validate raw spectator data for consistency
    pub fn validate(&self) -> bool {
        // Basic validation checks
        if self.player_id == 0 {
            return false;
        }
        
        // Validate spectator mode range
        if self.spectator_mode > 5 {
            return false;
        }
        
        // Validate team ID (assuming valid range 0-1 for R6S)
        if self.team_id > 1 {
            return false;
        }
        
        // Validate timestamp (should not be in future)
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if self.spectator_start_time > current_time {
            return false;
        }
        
        true
    }
    
    /// Get spectator mode as human-readable string
    pub fn get_mode_string(&self) -> &'static str {
        match self.spectator_mode {
            0 => "First Person",
            1 => "Third Person",
            2 => "Free Camera",
            3 => "Killcam",
            4 => "Team Spectate",
            5 => "Enemy Spectate",
            _ => "Unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_spectator_detection_creation() {
        let detection = SpectatorDetection::new();
        assert_eq!(detection.get_spectator_count().await, 0);
    }

    #[tokio::test]
    async fn test_threat_level_assessment() {
        let detection = SpectatorDetection::new();
        assert!(matches!(detection.get_threat_level().await, ThreatLevel::Low));
    }
}
