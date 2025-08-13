use serde::{Deserialize, Serialize};

// ESP data structures matching helper interface
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EspData {
    pub players: Vec<PlayerData>,
    pub gadgets: Vec<GadgetData>,
    pub objectives: Vec<ObjectiveData>,
    pub game_state: GameState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlayerData {
    pub entity_id: u32,
    pub position: Vector3,
    pub health: u32,
    pub team: Team,
    pub name: String,
    pub operator_id: u32,
    pub state: PlayerState,
    pub bones: Vec<Vector3>,
    pub distance: f32,
    pub visible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GadgetData {
    pub gadget_id: u32,
    pub gadget_type: GadgetType,
    pub position: Vector3,
    pub owner_id: u32,
    pub state: u32,
    pub distance: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectiveData {
    pub objective_type: ObjectiveType,
    pub position: Vector3,
    pub state: u32,
    pub timer: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameState {
    pub game_mode: u32,
    pub round_state: u32,
    pub bomb_planted: bool,
    pub bomb_timer: Option<f32>,
    pub spectator_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vector3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Team {
    Attackers = 0,
    Defenders = 1,
    Spectator = 2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlayerState {
    Alive = 0,
    Downed = 1,
    Dead = 2,
    Spectating = 3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GadgetType {
    Unknown = 0,
    Trap = 1,
    Camera = 2,
    Drone = 3,
    Destructible = 4,
    Breaching = 5,
    Throwable = 6,
    Utility = 7,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ObjectiveType {
    Bomb = 0,
    Hostage = 1,
    SecureArea = 2,
}

// ESP configuration matching helper config manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EspConfig {
    // Player ESP
    pub skeleton_enabled: bool,
    pub skeleton_color: String,
    pub box_enabled: bool,
    pub box_color: String,
    pub health_enabled: bool,
    pub health_color: String,
    pub name_enabled: bool,
    pub name_color: String,
    pub distance_enabled: bool,
    pub distance_color: String,
    pub weapon_enabled: bool,
    pub weapon_color: String,
    pub chams_enabled: bool,
    pub chams_color: String,
    pub head_dot_enabled: bool,
    pub head_dot_color: String,
    pub snaplines_enabled: bool,
    pub snaplines_color: String,
    pub visibility_check: bool,
    
    // Gadget ESP
    pub traps_enabled: bool,
    pub traps_color: String,
    pub cameras_enabled: bool,
    pub cameras_color: String,
    pub drones_enabled: bool,
    pub drones_color: String,
    pub destructibles_enabled: bool,
    pub destructibles_color: String,
    pub breaching_enabled: bool,
    pub breaching_color: String,
    pub throwables_enabled: bool,
    pub throwables_color: String,
    pub utility_enabled: bool,
    pub utility_color: String,
    
    // Environment ESP
    pub objectives_enabled: bool,
    pub objectives_color: String,
    pub bomb_sites_enabled: bool,
    pub bomb_sites_color: String,
    pub hostages_enabled: bool,
    pub hostages_color: String,
    
    // Performance
    pub max_distance: f32,
    pub fps_limit: u32,
    pub render_quality: f32,
}

impl Default for EspConfig {
    fn default() -> Self {
        Self {
            // Player ESP defaults
            skeleton_enabled: false,
            skeleton_color: "#FFFFFF".to_string(),
            box_enabled: false,
            box_color: "#FFFFFF".to_string(),
            health_enabled: false,
            health_color: "#00FF00".to_string(),
            name_enabled: false,
            name_color: "#FFFFFF".to_string(),
            distance_enabled: false,
            distance_color: "#FFFF00".to_string(),
            weapon_enabled: false,
            weapon_color: "#FFA500".to_string(),
            chams_enabled: false,
            chams_color: "#FF0000".to_string(),
            head_dot_enabled: false,
            head_dot_color: "#FF0000".to_string(),
            snaplines_enabled: false,
            snaplines_color: "#00FFFF".to_string(),
            visibility_check: true,
            
            // Gadget ESP defaults
            traps_enabled: false,
            traps_color: "#FF6600".to_string(),
            cameras_enabled: false,
            cameras_color: "#0066FF".to_string(),
            drones_enabled: false,
            drones_color: "#FFFF00".to_string(),
            destructibles_enabled: false,
            destructibles_color: "#FF9900".to_string(),
            breaching_enabled: false,
            breaching_color: "#FF0066".to_string(),
            throwables_enabled: false,
            throwables_color: "#66FF00".to_string(),
            utility_enabled: false,
            utility_color: "#00FF66".to_string(),
            
            // Environment ESP defaults
            objectives_enabled: false,
            objectives_color: "#FFFF00".to_string(),
            bomb_sites_enabled: false,
            bomb_sites_color: "#FF0000".to_string(),
            hostages_enabled: false,
            hostages_color: "#00FF00".to_string(),
            
            // Performance defaults
            max_distance: 500.0,
            fps_limit: 60,
            render_quality: 1.0,
        }
    }
}

impl EspConfig {
    pub fn get_color_rgba(&self, color_hex: &str) -> [f32; 4] {
        // Convert hex color to RGBA float array
        if let Ok(color) = hex_to_rgba(color_hex) {
            color
        } else {
            [1.0, 1.0, 1.0, 1.0] // Default white
        }
    }
}

fn hex_to_rgba(hex: &str) -> Result<[f32; 4], ()> {
    let hex = hex.trim_start_matches('#');
    
    if hex.len() != 6 {
        return Err(());
    }
    
    let r = u8::from_str_radix(&hex[0..2], 16).map_err(|_| ())?;
    let g = u8::from_str_radix(&hex[2..4], 16).map_err(|_| ())?;
    let b = u8::from_str_radix(&hex[4..6], 16).map_err(|_| ())?;
    
    Ok([
        r as f32 / 255.0,
        g as f32 / 255.0,
        b as f32 / 255.0,
        1.0, // Full alpha
    ])
}
