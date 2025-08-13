use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureConfig {
    pub enabled: bool,
    pub color: String,
    pub value: f32,
    pub last_updated: u64,
}

impl Default for FeatureConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            color: "#FFFFFF".to_string(),
            value: 1.0,
            last_updated: 0,
        }
    }
}

pub struct ConfigManager {
    features: RwLock<HashMap<String, FeatureConfig>>,
    pending_changes: RwLock<Vec<String>>,
}

impl ConfigManager {
    pub async fn new() -> Result<Self> {
        let mut features = HashMap::new();
        
        // Initialize all ESP features from web menu analysis
        let feature_names = vec![
            // Player ESP
            "skeleton", "box", "health", "name", "distance", "weapon", "chams",
            "head_dot", "snaplines", "visibility_check",
            
            // Gadget ESP
            "traps", "cameras", "drones", "destructibles", "breaching_charges",
            "throwables", "utility_gadgets",
            
            // Environment ESP
            "objectives", "bomb_sites", "hostages", "secure_areas", "entry_points",
            "reinforcements", "barricades",
            
            // Performance
            "max_distance", "fps_limit", "render_quality",
        ];

        for feature_name in feature_names {
            features.insert(feature_name.to_string(), FeatureConfig::default());
        }

        Ok(Self {
            features: RwLock::new(features),
            pending_changes: RwLock::new(Vec::new()),
        })
    }

    pub async fn update_feature(
        &self,
        feature_name: &str,
        enabled: bool,
        color: Option<String>,
        value: Option<f32>,
    ) -> Result<()> {
        let mut features = self.features.write().await;
        let mut pending = self.pending_changes.write().await;

        let config = features.entry(feature_name.to_string()).or_default();
        
        config.enabled = enabled;
        if let Some(color) = color {
            config.color = color;
        }
        if let Some(value) = value {
            config.value = value;
        }
        config.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Mark as pending change
        if !pending.contains(&feature_name.to_string()) {
            pending.push(feature_name.to_string());
        }

        Ok(())
    }

    pub async fn toggle_feature(&self, feature_name: &str, enabled: bool) -> Result<()> {
        self.update_feature(feature_name, enabled, None, None).await
    }

    pub async fn set_feature_color(&self, feature_name: &str, color: &str) -> Result<()> {
        let mut features = self.features.write().await;
        let mut pending = self.pending_changes.write().await;

        let config = features.entry(feature_name.to_string()).or_default();
        config.color = color.to_string();
        config.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if !pending.contains(&feature_name.to_string()) {
            pending.push(feature_name.to_string());
        }

        Ok(())
    }

    pub async fn get_feature(&self, feature_name: &str) -> Option<FeatureConfig> {
        let features = self.features.read().await;
        features.get(feature_name).cloned()
    }

    pub async fn get_all_features(&self) -> HashMap<String, FeatureConfig> {
        let features = self.features.read().await;
        features.clone()
    }

    pub async fn get_active_feature_count(&self) -> u32 {
        let features = self.features.read().await;
        features.values().filter(|config| config.enabled).count() as u32
    }

    pub fn has_pending_changes(&self) -> bool {
        // Non-async check for pending changes
        match self.pending_changes.try_read() {
            Ok(pending) => !pending.is_empty(),
            Err(_) => false,
        }
    }

    pub async fn apply_pending_changes(&self) -> Result<()> {
        let mut pending = self.pending_changes.write().await;
        
        if pending.is_empty() {
            return Ok(());
        }

        // In a real implementation, this would:
        // 1. Send configuration updates to the driver
        // 2. Notify the overlay of changes
        // 3. Update any persistent storage
        
        tracing::debug!("Applying {} pending configuration changes", pending.len());
        
        // Clear pending changes
        pending.clear();
        
        Ok(())
    }

    pub async fn get_esp_config(&self) -> EspConfig {
        let features = self.features.read().await;
        
        EspConfig {
            // Player ESP
            skeleton_enabled: features.get("skeleton").map(|f| f.enabled).unwrap_or(false),
            skeleton_color: features.get("skeleton").map(|f| f.color.clone()).unwrap_or_else(|| "#FFFFFF".to_string()),
            
            box_enabled: features.get("box").map(|f| f.enabled).unwrap_or(false),
            box_color: features.get("box").map(|f| f.color.clone()).unwrap_or_else(|| "#FFFFFF".to_string()),
            
            health_enabled: features.get("health").map(|f| f.enabled).unwrap_or(false),
            health_color: features.get("health").map(|f| f.color.clone()).unwrap_or_else(|| "#00FF00".to_string()),
            
            name_enabled: features.get("name").map(|f| f.enabled).unwrap_or(false),
            name_color: features.get("name").map(|f| f.color.clone()).unwrap_or_else(|| "#FFFFFF".to_string()),
            
            distance_enabled: features.get("distance").map(|f| f.enabled).unwrap_or(false),
            distance_color: features.get("distance").map(|f| f.color.clone()).unwrap_or_else(|| "#FFFF00".to_string()),
            
            weapon_enabled: features.get("weapon").map(|f| f.enabled).unwrap_or(false),
            weapon_color: features.get("weapon").map(|f| f.color.clone()).unwrap_or_else(|| "#FFA500".to_string()),
            
            chams_enabled: features.get("chams").map(|f| f.enabled).unwrap_or(false),
            chams_color: features.get("chams").map(|f| f.color.clone()).unwrap_or_else(|| "#FF0000".to_string()),
            
            head_dot_enabled: features.get("head_dot").map(|f| f.enabled).unwrap_or(false),
            head_dot_color: features.get("head_dot").map(|f| f.color.clone()).unwrap_or_else(|| "#FF0000".to_string()),
            
            snaplines_enabled: features.get("snaplines").map(|f| f.enabled).unwrap_or(false),
            snaplines_color: features.get("snaplines").map(|f| f.color.clone()).unwrap_or_else(|| "#00FFFF".to_string()),
            
            visibility_check: features.get("visibility_check").map(|f| f.enabled).unwrap_or(true),
            
            // Gadget ESP
            traps_enabled: features.get("traps").map(|f| f.enabled).unwrap_or(false),
            traps_color: features.get("traps").map(|f| f.color.clone()).unwrap_or_else(|| "#FF6600".to_string()),
            
            cameras_enabled: features.get("cameras").map(|f| f.enabled).unwrap_or(false),
            cameras_color: features.get("cameras").map(|f| f.color.clone()).unwrap_or_else(|| "#0066FF".to_string()),
            
            drones_enabled: features.get("drones").map(|f| f.enabled).unwrap_or(false),
            drones_color: features.get("drones").map(|f| f.color.clone()).unwrap_or_else(|| "#FFFF00".to_string()),
            
            destructibles_enabled: features.get("destructibles").map(|f| f.enabled).unwrap_or(false),
            destructibles_color: features.get("destructibles").map(|f| f.color.clone()).unwrap_or_else(|| "#FF9900".to_string()),
            
            breaching_enabled: features.get("breaching_charges").map(|f| f.enabled).unwrap_or(false),
            breaching_color: features.get("breaching_charges").map(|f| f.color.clone()).unwrap_or_else(|| "#FF0066".to_string()),
            
            throwables_enabled: features.get("throwables").map(|f| f.enabled).unwrap_or(false),
            throwables_color: features.get("throwables").map(|f| f.color.clone()).unwrap_or_else(|| "#66FF00".to_string()),
            
            utility_enabled: features.get("utility_gadgets").map(|f| f.enabled).unwrap_or(false),
            utility_color: features.get("utility_gadgets").map(|f| f.color.clone()).unwrap_or_else(|| "#00FF66".to_string()),
            
            // Environment ESP
            objectives_enabled: features.get("objectives").map(|f| f.enabled).unwrap_or(false),
            objectives_color: features.get("objectives").map(|f| f.color.clone()).unwrap_or_else(|| "#FFFF00".to_string()),
            
            bomb_sites_enabled: features.get("bomb_sites").map(|f| f.enabled).unwrap_or(false),
            bomb_sites_color: features.get("bomb_sites").map(|f| f.color.clone()).unwrap_or_else(|| "#FF0000".to_string()),
            
            hostages_enabled: features.get("hostages").map(|f| f.enabled).unwrap_or(false),
            hostages_color: features.get("hostages").map(|f| f.color.clone()).unwrap_or_else(|| "#00FF00".to_string()),
            
            // Performance
            max_distance: features.get("max_distance").map(|f| f.value).unwrap_or(500.0),
            fps_limit: features.get("fps_limit").map(|f| f.value as u32).unwrap_or(60),
            render_quality: features.get("render_quality").map(|f| f.value).unwrap_or(1.0),
        }
    }
}

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
