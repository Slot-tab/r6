// Solara ESP - Web Bridge Communication System
// Rainbow Six Siege / BattlEye Anti-Cheat
// Handles communication between cheat backend and SolaraWeb UI

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use warp::Filter;

use futures_util::{SinkExt, StreamExt};
use chrono;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebConfig {
    pub esp: EspConfig,
    pub aimbot: AimbotConfig,
    pub performance: PerformanceConfig,
    pub spectators: SpectatorConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EspConfig {
    pub wallhack: bool,
    pub esp_boxes: bool,
    pub health_bars: bool,
    pub name_tags: bool,
    pub radar: bool,
    pub crosshair: bool,
    pub box_color: String,
    pub health_color: String,
    pub name_color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AimbotConfig {
    pub enabled: bool,
    pub trigger_bot: bool,
    pub smoothness: f32,
    pub fov: f32,
    pub target_bone: String,
    pub auto_fire: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub fps_limit: u32,
    pub esp_distance: f32,
    pub high_performance_mode: bool,
    pub render_quality: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpectatorConfig {
    pub enabled: bool,
    pub show_list: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpectatorInfo {
    pub name: String,
    pub duration: u64, // seconds
    pub is_suspicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub game_running: bool,
    pub driver_loaded: bool,
    pub stealth_active: bool,
    pub memory_usage: u64,
    pub cpu_usage: f32,
    pub spectators: Vec<SpectatorInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebMessage {
    pub message_type: String,
    pub data: serde_json::Value,
}

pub struct WebBridge {
    config: Arc<RwLock<WebConfig>>,
    status: Arc<RwLock<SystemStatus>>,
    clients: Arc<Mutex<Vec<futures_util::stream::SplitSink<warp::ws::WebSocket, warp::ws::Message>>>>,
}

impl WebBridge {
    pub fn new() -> Self {
        let default_config = WebConfig {
            esp: EspConfig {
                wallhack: false,
                esp_boxes: false,
                health_bars: false,
                name_tags: false,
                radar: false,
                crosshair: false,
                box_color: "#00ff00".to_string(),
                health_color: "#ff0000".to_string(),
                name_color: "#ffffff".to_string(),
            },
            aimbot: AimbotConfig {
                enabled: false,
                trigger_bot: false,
                smoothness: 50.0,
                fov: 60.0,
                target_bone: "head".to_string(),
                auto_fire: false,
            },
            performance: PerformanceConfig {
                fps_limit: 60,
                esp_distance: 50.0,
                high_performance_mode: false,
                render_quality: "medium".to_string(),
            },
            spectators: SpectatorConfig {
                enabled: true,
                show_list: true,
            },
        };

        let default_status = SystemStatus {
            game_running: false,
            driver_loaded: false,
            stealth_active: true,
            memory_usage: 0,
            cpu_usage: 0.0,
            spectators: Vec::new(),
        };

        Self {
            config: Arc::new(RwLock::new(default_config)),
            status: Arc::new(RwLock::new(default_status)),
            clients: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn start_server(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config = self.config.clone();
        let status = self.status.clone();
        let clients = self.clients.clone();

        // CORS headers for web requests
        let cors = warp::cors()
            .allow_any_origin()
            .allow_headers(vec!["content-type", "authorization"])
            .allow_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"]);

        // API Routes
        let api_config = warp::path("api")
            .and(warp::path("config"))
            .and(warp::get())
            .and_then({
                let config = config.clone();
                move || {
                    let config = config.clone();
                    async move {
                        let config = config.read().await;
                        Ok::<_, warp::Rejection>(warp::reply::json(&*config))
                    }
                }
            });

        let api_config_update = warp::path("api")
            .and(warp::path("config"))
            .and(warp::post())
            .and(warp::body::json())
            .and_then({
                let config = config.clone();
                let clients = clients.clone();
                move |new_config: WebConfig| {
                    let config = config.clone();
                    let clients = clients.clone();
                    async move {
                        {
                            let mut config_guard = config.write().await;
                            *config_guard = new_config.clone();
                        }

                        // Broadcast config update to all connected clients
                        let message = WebMessage {
                            message_type: "config_update".to_string(),
                            data: serde_json::to_value(&new_config).unwrap(),
                        };
                        
                        Self::broadcast_to_clients(&clients, &message).await;

                        Ok::<_, warp::Rejection>(warp::reply::json(&serde_json::json!({
                            "success": true,
                            "message": "Configuration updated successfully"
                        })))
                    }
                }
            });

        let api_status = warp::path("api")
            .and(warp::path("status"))
            .and(warp::get())
            .and_then({
                let status = status.clone();
                move || {
                    let status = status.clone();
                    async move {
                        let status = status.read().await;
                        Ok::<_, warp::Rejection>(warp::reply::json(&*status))
                    }
                }
            });

        // WebSocket endpoint
        let websocket = warp::path("ws")
            .and(warp::ws())
            .and_then({
                let clients = clients.clone();
                move |ws: warp::ws::Ws| {
                    let clients = clients.clone();
                    async move {
                        Ok::<_, warp::Rejection>(ws.on_upgrade(move |websocket| {
                            Self::handle_websocket(websocket, clients)
                        }))
                    }
                }
            });

        // Static file serving for SolaraWeb
        let static_files = warp::fs::dir("web/");

        // Combine all routes
        let routes = api_config
            .or(api_config_update)
            .or(api_status)
            .or(websocket)
            .or(static_files)
            .with(cors);

        println!("🌐 Web Bridge starting on http://localhost:8080");
        println!("📱 SolaraWeb UI available at http://localhost:8080/Menu/");

        warp::serve(routes)
            .run(([127, 0, 0, 1], 8080))
            .await;

        Ok(())
    }

    async fn handle_websocket(
        websocket: warp::ws::WebSocket,
        clients: Arc<Mutex<Vec<futures_util::stream::SplitSink<warp::ws::WebSocket, warp::ws::Message>>>>,
    ) {
        let (ws_sender, mut ws_receiver) = websocket.split();
        
        // Add this client to the clients list
        {
            let mut clients_guard = clients.lock().await;
            clients_guard.push(ws_sender);
        }

        // Handle incoming messages
        while let Some(result) = ws_receiver.next().await {
            match result {
                Ok(msg) => {
                    if msg.is_text() {
                        if let Ok(text) = msg.to_str() {
                            if let Ok(web_msg) = serde_json::from_str::<WebMessage>(text) {
                                println!("📨 Received WebSocket message: {}", web_msg.message_type);
                                
                                // Handle different message types
                                match web_msg.message_type.as_str() {
                                    "ping" => {
                                        let pong = WebMessage {
                                            message_type: "pong".to_string(),
                                            data: serde_json::json!({"timestamp": chrono::Utc::now().timestamp()}),
                                        };
                                        if let Ok(pong_text) = serde_json::to_string(&pong) {
                                            // Send pong response through any available client
                                            Self::broadcast_to_clients(&clients, &pong).await;
                                        }
                                    },
                                    "config_change" => {
                                        // Handle real-time configuration changes
                                        println!("⚙️ Configuration change received");
                                    },
                                    _ => {
                                        println!("❓ Unknown message type: {}", web_msg.message_type);
                                    }
                                }
                            }
                        }
                    }
                },
                Err(e) => {
                    println!("❌ WebSocket error: {}", e);
                    break;
                }
            }
        }
    }

    async fn broadcast_to_clients(
        clients: &Arc<Mutex<Vec<futures_util::stream::SplitSink<warp::ws::WebSocket, warp::ws::Message>>>>,
        message: &WebMessage,
    ) {
        if let Ok(message_text) = serde_json::to_string(message) {
            let mut clients_guard = clients.lock().await;
            let mut to_remove = Vec::new();
            for (i, client) in clients_guard.iter_mut().enumerate() {
                if let Err(_) = client.send(warp::ws::Message::text(message_text.clone())).await {
                    // Failed to send message, mark client for removal
                    to_remove.push(i);
                }
            }
            
            // Remove failed clients in reverse order to maintain indices
            for &index in to_remove.iter().rev() {
                clients_guard.remove(index);
            }
        }
    }

    pub async fn update_status(&self, new_status: SystemStatus) {
        {
            let mut status_guard = self.status.write().await;
            *status_guard = new_status.clone();
        }

        // Broadcast status update to all connected clients
        let message = WebMessage {
            message_type: "status_update".to_string(),
            data: serde_json::to_value(&new_status).unwrap(),
        };
        
        Self::broadcast_to_clients(&self.clients, &message).await;
    }

    pub async fn update_spectators(&self, spectators: Vec<SpectatorInfo>) {
        {
            let mut status_guard = self.status.write().await;
            status_guard.spectators = spectators.clone();
        }

        // Broadcast spectator update to all connected clients
        let message = WebMessage {
            message_type: "spectators_update".to_string(),
            data: serde_json::to_value(&spectators).unwrap(),
        };
        
        Self::broadcast_to_clients(&self.clients, &message).await;
    }

    pub async fn get_config(&self) -> WebConfig {
        self.config.read().await.clone()
    }

    pub async fn get_status(&self) -> SystemStatus {
        self.status.read().await.clone()
    }

    // Performance slider auto-save fix
    pub async fn update_performance_setting(&self, setting: &str, value: f32) {
        {
            let mut config_guard = self.config.write().await;
            match setting {
                "fps" => config_guard.performance.fps_limit = value as u32,
                "distance" => config_guard.performance.esp_distance = value,
                _ => {}
            }
        }

        // Immediately broadcast the change to ensure auto-save works
        let config = self.get_config().await;
        let message = WebMessage {
            message_type: "performance_update".to_string(),
            data: serde_json::json!({
                "setting": setting,
                "value": value,
                "config": config.performance
            }),
        };
        
        Self::broadcast_to_clients(&self.clients, &message).await;
        println!("💾 Performance setting '{}' updated to: {}", setting, value);
    }

    // Simplified spectator detection
    pub async fn add_spectator(&self, name: String) {
        let spectator = SpectatorInfo {
            name: name.clone(),
            duration: 0,
            is_suspicious: false,
        };

        {
            let mut status_guard = self.status.write().await;
            // Check if spectator already exists
            if !status_guard.spectators.iter().any(|s| s.name == name) {
                status_guard.spectators.push(spectator);
            }
        }

        let spectators = self.status.read().await.spectators.clone();
        self.update_spectators(spectators).await;
        println!("👁️ Spectator added: {}", name);
    }

    pub async fn remove_spectator(&self, name: &str) {
        {
            let mut status_guard = self.status.write().await;
            status_guard.spectators.retain(|s| s.name != name);
        }

        let spectators = self.status.read().await.spectators.clone();
        self.update_spectators(spectators).await;
        println!("👁️ Spectator removed: {}", name);
    }

    pub async fn get_spectators(&self) -> Vec<SpectatorInfo> {
        self.status.read().await.spectators.clone()
    }
}
