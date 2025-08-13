// Rainbow Six Siege Specific Offsets and Game Data Structures
// All offsets are for the current R6S build and will be auto-updated

use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Rainbow Six Siege game offsets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R6SOffsets {
    // Core game offsets
    pub game_manager: usize,
    pub local_player: usize,
    pub player_list: usize,
    pub entity_list: usize,
    pub camera_manager: usize,
    pub round_manager: usize,
    
    // Player structure offsets
    pub player_health: usize,
    pub player_position: usize,
    pub player_rotation: usize,
    pub player_team: usize,
    pub player_name: usize,
    pub player_operator: usize,
    pub player_state: usize,
    pub player_weapon: usize,
    
    // Entity offsets
    pub entity_position: usize,
    pub entity_type: usize,
    pub entity_health: usize,
    pub entity_team: usize,
    
    // Camera offsets
    pub camera_position: usize,
    pub camera_rotation: usize,
    pub view_matrix: usize,
    pub projection_matrix: usize,
    
    // Spectator specific offsets
    pub spectator_list: usize,
    pub spectator_target: usize,
    pub spectator_mode: usize,
    
    // Game state offsets
    pub game_state: usize,
    pub round_time: usize,
    pub match_score: usize,
    pub prep_phase: usize,
}

impl Default for R6SOffsets {
    fn default() -> Self {
        Self {
            // All offsets start at 0 and are populated by the automated offset updater
            // NEVER hardcode offsets - they are discovered dynamically via signature scanning
            game_manager: 0,
            local_player: 0,
            player_list: 0,
            entity_list: 0,
            camera_manager: 0,
            round_manager: 0,
            
            player_health: 0,
            player_position: 0,
            player_rotation: 0,
            player_team: 0,
            player_name: 0,
            player_operator: 0,
            player_state: 0,
            player_weapon: 0,
            
            entity_position: 0,
            entity_type: 0,
            entity_health: 0,
            entity_team: 0,
            
            camera_position: 0,
            camera_rotation: 0,
            view_matrix: 0,
            projection_matrix: 0,
            
            spectator_list: 0,
            spectator_target: 0,
            spectator_mode: 0,
            
            game_state: 0,
            round_time: 0,
            match_score: 0,
            prep_phase: 0,
        }
    }
}

/// Rainbow Six Siege operator information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R6SOperator {
    pub id: u32,
    pub name: String,
    pub team: R6STeam,
    pub role: R6SRole,
    pub gadget: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum R6STeam {
    Attacker,
    Defender,
    Spectator,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum R6SRole {
    Assault,
    Support,
    Intel,
    Breach,
    AntiGadget,
    Anchor,
    Roamer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum R6SGameState {
    MainMenu,
    MatchMaking,
    Loading,
    PrepPhase,
    ActionPhase,
    EndRound,
    EndMatch,
}

/// Rainbow Six Siege specific game data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R6SGameData {
    pub local_player: Option<R6SPlayer>,
    pub players: Vec<R6SPlayer>,
    pub entities: Vec<R6SEntity>,
    pub spectators: Vec<R6SSpectator>,
    pub game_state: R6SGameState,
    pub round_time: f32,
    pub score_blue: u32,
    pub is_prep_phase: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R6SPlayer {
    pub id: u32,
    pub name: String,
    pub health: f32,
    pub max_health: f32,
    pub position: [f32; 3],
    pub rotation: [f32; 3],
    pub team: R6STeam,
    pub operator: Option<R6SOperator>,
    pub is_alive: bool,
    pub is_downed: bool,
    pub weapon: Option<String>,
    pub ping: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R6SEntity {
    pub id: u32,
    pub entity_type: R6SEntityType,
    pub position: [f32; 3],
    pub health: f32,
    pub team: R6STeam,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum R6SEntityType {
    Gadget,
    Drone,
    Camera,
    Breach,
    Trap,
    Utility,
    Hostage,
    Bomb,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R6SSpectator {
    pub player_id: u32,
    pub player_name: String,
    pub target_id: Option<u32>,
    pub spectator_mode: R6SSpectatorMode,
    pub join_time: std::time::SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum R6SSpectatorMode {
    FirstPerson,
    ThirdPerson,
    Free,
    Overview,
    Drone,
}

/// Rainbow Six Siege operator database
pub struct R6SOperatorDB {
    operators: HashMap<u32, R6SOperator>,
}

impl R6SOperatorDB {
    pub fn new() -> Self {
        let mut operators = HashMap::new();
        
        // Attackers
        operators.insert(1, R6SOperator {
            id: 1,
            name: "Sledge".to_string(),
            team: R6STeam::Attacker,
            role: R6SRole::Breach,
            gadget: "Breaching Hammer".to_string(),
        });
        
        operators.insert(2, R6SOperator {
            id: 2,
            name: "Thatcher".to_string(),
            team: R6STeam::Attacker,
            role: R6SRole::AntiGadget,
            gadget: "EMP Grenades".to_string(),
        });
        
        operators.insert(3, R6SOperator {
            id: 3,
            name: "Ash".to_string(),
            team: R6STeam::Attacker,
            role: R6SRole::Breach,
            gadget: "Breaching Rounds".to_string(),
        });
        
        operators.insert(4, R6SOperator {
            id: 4,
            name: "Thermite".to_string(),
            team: R6STeam::Attacker,
            role: R6SRole::Breach,
            gadget: "Exothermic Charge".to_string(),
        });
        
        operators.insert(5, R6SOperator {
            id: 5,
            name: "Twitch".to_string(),
            team: R6STeam::Attacker,
            role: R6SRole::AntiGadget,
            gadget: "Shock Drone".to_string(),
        });
        
        // Defenders
        operators.insert(101, R6SOperator {
            id: 101,
            name: "Smoke".to_string(),
            team: R6STeam::Defender,
            role: R6SRole::Anchor,
            gadget: "Remote Gas Grenade".to_string(),
        });
        
        operators.insert(102, R6SOperator {
            id: 102,
            name: "Mute".to_string(),
            team: R6STeam::Defender,
            role: R6SRole::AntiGadget,
            gadget: "Signal Disruptor".to_string(),
        });
        
        operators.insert(103, R6SOperator {
            id: 103,
            name: "Castle".to_string(),
            team: R6STeam::Defender,
            role: R6SRole::Anchor,
            gadget: "Armor Panel".to_string(),
        });
        
        operators.insert(104, R6SOperator {
            id: 104,
            name: "Pulse".to_string(),
            team: R6STeam::Defender,
            role: R6SRole::Intel,
            gadget: "Heartbeat Sensor".to_string(),
        });
        
        operators.insert(105, R6SOperator {
            id: 105,
            name: "Doc".to_string(),
            team: R6STeam::Defender,
            role: R6SRole::Support,
            gadget: "Stim Pistol".to_string(),
        });
        
        Self { operators }
    }
    
    pub fn get_operator(&self, id: u32) -> Option<&R6SOperator> {
        self.operators.get(&id)
    }
    
    pub fn get_all_operators(&self) -> Vec<&R6SOperator> {
        self.operators.values().collect()
    }
    
    pub fn get_attackers(&self) -> Vec<&R6SOperator> {
        self.operators.values()
            .filter(|op| op.team == R6STeam::Attacker)
            .collect()
    }
    
    pub fn get_defenders(&self) -> Vec<&R6SOperator> {
        self.operators.values()
            .filter(|op| op.team == R6STeam::Defender)
            .collect()
    }
}

/// Rainbow Six Siege map information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R6SMap {
    pub name: String,
    pub bounds_min: [f32; 3],
    pub bounds_max: [f32; 3],
    pub spawn_points: Vec<[f32; 3]>,
    pub objective_locations: Vec<[f32; 3]>,
}

impl Default for R6SMap {
    fn default() -> Self {
        R6SMap {
            name: "Default_Map".to_string(),
            bounds_min: [-1000.0, -1000.0, -100.0],
            bounds_max: [1000.0, 1000.0, 100.0],
            spawn_points: vec![
                [0.0, 0.0, 0.0],
                [100.0, 100.0, 0.0],
                [-100.0, -100.0, 0.0],
            ],
            objective_locations: vec![
                [50.0, 50.0, 0.0],
                [-50.0, -50.0, 0.0],
            ],
        }
    }
}

impl R6SMap {
    /// Validate player positions during ESP rendering
    pub fn validate_all_player_positions(&self, players: &[(u32, [f32; 3])]) -> Vec<(u32, bool)> {
        players.iter()
            .map(|(id, pos)| (*id, self.validate_player_position(*pos)))
            .collect()
    }

    /// Check if multiple positions are within map bounds
    #[allow(dead_code)]
    pub fn check_positions_in_bounds(&self, positions: &[[f32; 3]]) -> Vec<bool> {
        positions.iter()
            .map(|pos| self.is_position_in_bounds(*pos))
            .collect()
    }

    pub fn is_position_in_bounds(&self, position: [f32; 3]) -> bool {
        // Check if position is within map boundaries
        let in_bounds = position[0] >= self.bounds_min[0] && position[0] <= self.bounds_max[0] &&
                       position[1] >= self.bounds_min[1] && position[1] <= self.bounds_max[1] &&
                       position[2] >= self.bounds_min[2] && position[2] <= self.bounds_max[2];
        
        tracing::debug!("Position bounds check for {:?}: {} (bounds: {:?} to {:?})", 
                       position, in_bounds, self.bounds_min, self.bounds_max);
        in_bounds
    }
    
    pub fn validate_player_position(&self, position: [f32; 3]) -> bool {
        // Use the is_position_in_bounds method for player position validation
        if !self.is_position_in_bounds(position) {
            tracing::warn!("Player position {:?} is outside map bounds for {}", position, self.name);
            return false;
        }
        true
    }
}

/// Rainbow Six Siege configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R6SConfig {
    pub offsets: R6SOffsets,
    pub operator_db: bool, // Whether to load operator database
    pub spectator_detection_enabled: bool,
    pub auto_offset_updates: bool,
    pub max_render_distance: f32,
    pub show_friendly_players: bool,
    pub show_enemy_players: bool,
    pub show_spectators: bool,
    pub show_gadgets: bool,
    pub show_drones: bool,
    pub show_cameras: bool,
}

impl R6SConfig {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for R6SConfig {
    fn default() -> Self {
        Self {
            offsets: R6SOffsets::default(),
            operator_db: true,
            spectator_detection_enabled: true,
            auto_offset_updates: true,
            max_render_distance: 1000.0,
            show_friendly_players: true,
            show_enemy_players: true,
            show_spectators: true,
            show_gadgets: true,
            show_drones: true,
            show_cameras: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_r6s_offsets() {
        let offsets = R6SOffsets::default();
        assert!(offsets.game_manager > 0);
        assert!(offsets.local_player > 0);
    }
    
    #[test]
    fn test_operator_db() {
        let db = R6SOperatorDB::new();
        let sledge = db.get_operator(1).unwrap();
        assert_eq!(sledge.name, "Sledge");
        assert_eq!(sledge.team, R6STeam::Attacker);
    }
    
    #[test]
    fn test_map_bounds() {
        let map = R6SMap {
            name: "House".to_string(),
            bounds_min: [-100.0, -100.0, -10.0],
            bounds_max: [100.0, 100.0, 50.0],
            spawn_points: vec![],
            objective_locations: vec![],
        };
        
        assert!(map.is_position_in_bounds([0.0, 0.0, 0.0]));
        assert!(!map.is_position_in_bounds([200.0, 0.0, 0.0]));
    }
}
