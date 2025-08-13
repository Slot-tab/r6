// Test Mode System - Allows testing without Rainbow Six Siege installed
// Provides fake data for development and testing purposes

use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::r6s_offsets::*;
use rand::Rng;

/// Test mode configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestModeConfig {
    pub enabled: bool,
    pub simulate_game_running: bool,
    pub simulate_spectators: bool,
    pub fake_player_count: usize,
    pub fake_entity_count: usize,
    pub update_interval_ms: u64,
}

impl Default for TestModeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            simulate_game_running: false,
            simulate_spectators: false,
            fake_player_count: 10,
            fake_entity_count: 15,
            update_interval_ms: 100,
        }
    }
}

/// Test mode data generator
pub struct TestModeManager {
    config: TestModeConfig,
    fake_game_data: Arc<RwLock<R6SGameData>>,
    is_running: bool,
}

impl TestModeManager {
    pub fn new() -> Self {
        Self {
            config: TestModeConfig::default(),
            fake_game_data: Arc::new(RwLock::new(Self::generate_initial_fake_data())),
            is_running: false,
        }
    }
    
    pub fn with_config(config: TestModeConfig) -> Self {
        Self {
            config: config.clone(),
            fake_game_data: Arc::new(RwLock::new(Self::generate_initial_fake_data())),
            is_running: false,
        }
    }
    
    /// Enable test mode
    pub async fn enable_test_mode(&mut self) -> Result<()> {
        self.config.enabled = true;
        self.config.simulate_game_running = true;
        
        // Start fake data generation
        self.start_fake_data_generation().await?;
        
        tracing::info!("Test mode enabled - simulating R6S data without game installed");
        Ok(())
    }
    
    /// Disable test mode
    pub async fn disable_test_mode(&mut self) -> Result<()> {
        self.config.enabled = false;
        self.config.simulate_game_running = false;
        self.is_running = false;
        
        tracing::info!("Test mode disabled");
        Ok(())
    }
    
    /// Check if test mode is enabled
    pub fn is_test_mode_enabled(&self) -> bool {
        self.config.enabled
    }
    
    /// Check if game is simulated as running
    pub fn is_game_simulated(&self) -> bool {
        self.config.simulate_game_running
    }
    
    /// Get fake game data
    pub async fn get_fake_game_data(&self) -> R6SGameData {
        self.fake_game_data.read().await.clone()
    }
    
    /// Start generating fake data
    async fn start_fake_data_generation(&mut self) -> Result<()> {
        if self.is_running {
            return Ok(());
        }
        
        self.is_running = true;
        let fake_data = Arc::clone(&self.fake_game_data);
        let config = self.config.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                tokio::time::Duration::from_millis(config.update_interval_ms)
            );
            
            while config.enabled {
                interval.tick().await;
                
                // Update fake data
                let mut data = fake_data.write().await;
                Self::update_fake_data(&mut data, &config).await;
            }
        });
        
        Ok(())
    }
    
    /// Generate initial fake data
    fn generate_initial_fake_data() -> R6SGameData {
        let mut rng = rand::thread_rng();
        
        // Generate fake players
        let mut players = Vec::new();
        for i in 0..10 {
            players.push(R6SPlayer {
                id: i,
                name: format!("TestPlayer{}", i),
                health: rng.gen_range(0.0..100.0),
                max_health: 100.0,
                position: [
                    rng.gen_range(-100.0..100.0),
                    rng.gen_range(-100.0..100.0),
                    rng.gen_range(0.0..50.0),
                ],
                rotation: [
                    rng.gen_range(0.0..360.0),
                    rng.gen_range(-90.0..90.0),
                    0.0,
                ],
                team: if i < 5 { R6STeam::Attacker } else { R6STeam::Defender },
                operator: Some(R6SOperator {
                    id: i + 1,
                    name: format!("TestOp{}", i),
                    team: if i < 5 { R6STeam::Attacker } else { R6STeam::Defender },
                    role: R6SRole::Assault,
                    gadget: "Test Gadget".to_string(),
                }),
                is_alive: rng.gen_bool(0.8),
                is_downed: rng.gen_bool(0.1),
                weapon: Some("Test Weapon".to_string()),
                ping: rng.gen_range(10..100),
            });
        }
        
        // Generate fake entities
        let mut entities = Vec::new();
        for i in 0..15 {
            entities.push(R6SEntity {
                id: i,
                entity_type: match i % 4 {
                    0 => R6SEntityType::Gadget,
                    1 => R6SEntityType::Drone,
                    2 => R6SEntityType::Camera,
                    _ => R6SEntityType::Utility,
                },
                position: [
                    rng.gen_range(-100.0..100.0),
                    rng.gen_range(-100.0..100.0),
                    rng.gen_range(0.0..50.0),
                ],
                health: rng.gen_range(0.0..100.0),
                team: if rng.gen_bool(0.5) { R6STeam::Attacker } else { R6STeam::Defender },
                is_active: rng.gen_bool(0.9),
            });
        }
        
        // Generate fake spectators
        let mut spectators = Vec::new();
        for i in 0..3 {
            spectators.push(R6SSpectator {
                player_id: 100 + i,
                player_name: format!("Spectator{}", i),
                target_id: Some(i % 10),
                spectator_mode: R6SSpectatorMode::FirstPerson,
                join_time: std::time::SystemTime::now(),
            });
        }
        
        R6SGameData {
            local_player: players.first().cloned(),
            players,
            entities,
            spectators,
            game_state: R6SGameState::ActionPhase,
            round_time: 180.0,
            score_blue: 2,

            is_prep_phase: false,
        }
    }
    
    /// Update fake data with random changes
    async fn update_fake_data(data: &mut R6SGameData, config: &TestModeConfig) {
        let mut rng = rand::thread_rng();
        
        // Update round time
        if data.round_time > 0.0 {
            data.round_time -= 0.1;
        } else {
            data.round_time = 180.0;
            data.game_state = match data.game_state {
                R6SGameState::PrepPhase => R6SGameState::ActionPhase,
                R6SGameState::ActionPhase => R6SGameState::EndRound,
                R6SGameState::EndRound => R6SGameState::PrepPhase,
                _ => R6SGameState::ActionPhase,
            };
        }
        
        // Randomly update player positions and health
        for player in &mut data.players {
            if player.is_alive {
                // Small random movement
                player.position[0] += rng.gen_range(-1.0..1.0);
                player.position[1] += rng.gen_range(-1.0..1.0);
                
                // Random health changes
                if rng.gen_bool(0.1) {
                    player.health = (player.health + rng.gen_range(-5.0..2.0)).clamp(0.0, 100.0);
                    if player.health <= 0.0 {
                        player.is_alive = false;
                    }
                }
            }
        }
        
        // Update spectators if enabled
        if config.simulate_spectators {
            for spectator in &mut data.spectators {
                // Randomly change spectator targets
                if rng.gen_bool(0.05) {
                    spectator.target_id = Some(rng.gen_range(0..data.players.len() as u32));
                }
            }
        }
    }
    
    /// Get test mode status for web API
    pub fn get_test_mode_status(&self) -> TestModeStatus {
        TestModeStatus {
            enabled: self.config.enabled,
            game_simulated: self.config.simulate_game_running,
            spectators_simulated: self.config.simulate_spectators,
            fake_player_count: self.config.fake_player_count,
            fake_entity_count: self.config.fake_entity_count,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TestModeStatus {
    pub enabled: bool,
    pub game_simulated: bool,
    pub spectators_simulated: bool,
    pub fake_player_count: usize,
    pub fake_entity_count: usize,
}

/// Check if Rainbow Six Siege is actually running
pub async fn is_r6s_running() -> bool {
    use std::process::Command;
    
    // Check if RainbowSix.exe process is running
    let output = Command::new("tasklist")
        .args(&["/FI", "IMAGENAME eq RainbowSix.exe"])
        .output();
        
    if let Ok(output) = output {
        let output_str = String::from_utf8_lossy(&output.stdout);
        output_str.contains("RainbowSix.exe")
    } else {
        false
    }
}

/// Determine system status (game running, test mode, or inactive)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SystemStatus {
    Active,      // R6S is running and cheat is operational
    TestMode,    // Test mode is enabled (no game required)
    Inactive,    // No game running and no test mode
}

impl SystemStatus {
    pub fn to_string(&self) -> String {
        match self {
            SystemStatus::Active => "Active".to_string(),
            SystemStatus::TestMode => "Test Mode".to_string(),
            SystemStatus::Inactive => "Inactive".to_string(),
        }
    }
    
    pub fn get_color(&self) -> String {
        match self {
            SystemStatus::Active => "green".to_string(),
            SystemStatus::TestMode => "blue".to_string(),
            SystemStatus::Inactive => "orange".to_string(),
        }
    }
    
    pub fn settings_locked(&self) -> bool {
        match self {
            SystemStatus::Active | SystemStatus::TestMode => false,
            SystemStatus::Inactive => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_test_mode_manager() {
        let mut manager = TestModeManager::new();
        assert!(!manager.is_test_mode_enabled());
        
        manager.enable_test_mode().await.unwrap();
        assert!(manager.is_test_mode_enabled());
        
        let fake_data = manager.get_fake_game_data().await;
        assert!(!fake_data.players.is_empty());
        assert!(!fake_data.entities.is_empty());
    }
    
    #[test]
    fn test_system_status() {
        assert_eq!(SystemStatus::Active.to_string(), "Active");
        assert_eq!(SystemStatus::Active.get_color(), "green");
        assert!(!SystemStatus::Active.settings_locked());
        
        assert_eq!(SystemStatus::Inactive.to_string(), "Inactive");
        assert_eq!(SystemStatus::Inactive.get_color(), "orange");
        assert!(SystemStatus::Inactive.settings_locked());
    }
}
