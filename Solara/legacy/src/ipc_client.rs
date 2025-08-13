use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::esp_data::{EspData, EspConfig};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OverlayMessage {
    message_type: String,
    data: serde_json::Value,
    timestamp: u64,
}

pub struct IpcClient {
    websocket: Option<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>,
    helper_url: String,
    connected: bool,
    last_heartbeat: std::time::Instant,
}

impl IpcClient {
    pub async fn new() -> Result<Self> {
        let helper_url = "ws://127.0.0.1:8081".to_string();
        let mut client = Self {
            websocket: None,
            helper_url,
            connected: false,
            last_heartbeat: std::time::Instant::now(),
        };

        client.connect().await?;
        Ok(client)
    }

    async fn connect(&mut self) -> Result<()> {
        tracing::info!("Connecting to helper at {}", self.helper_url);

        match connect_async(&self.helper_url).await {
            Ok((ws_stream, _)) => {
                self.websocket = Some(ws_stream);
                self.connected = true;
                self.last_heartbeat = std::time::Instant::now();
                tracing::info!("Connected to helper successfully");
                Ok(())
            }
            Err(e) => {
                self.connected = false;
                Err(anyhow::anyhow!("Failed to connect to helper: {}", e))
            }
        }
    }

    pub async fn is_connected(&self) -> bool {
        self.connected
    }

    pub async fn reconnect(&mut self) -> Result<()> {
        self.connected = false;
        self.websocket = None;
        
        // Wait a bit before reconnecting
        tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
        
        self.connect().await
    }

    pub async fn receive_esp_data(&mut self) -> Result<Option<EspData>> {
        if let Some(websocket) = &mut self.websocket {
            // Try to receive a message without blocking
            match websocket.next().await {
                Some(Ok(Message::Text(text))) => {
                    match serde_json::from_str::<OverlayMessage>(&text) {
                        Ok(message) => {
                            if message.message_type == "esp_data" {
                                match serde_json::from_value::<EspData>(message.data) {
                                    Ok(esp_data) => {
                                        self.last_heartbeat = std::time::Instant::now();
                                        return Ok(Some(esp_data));
                                    }
                                    Err(e) => {
                                        tracing::debug!("Failed to deserialize ESP data: {}", e);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!("Failed to parse message: {}", e);
                        }
                    }
                }
                Some(Ok(Message::Close(_))) => {
                    tracing::info!("Helper closed connection");
                    self.connected = false;
                    return Err(anyhow::anyhow!("Connection closed by helper"));
                }
                Some(Err(e)) => {
                    tracing::warn!("WebSocket error: {}", e);
                    self.connected = false;
                    return Err(anyhow::anyhow!("WebSocket error: {}", e));
                }
                None => {
                    // Connection closed
                    self.connected = false;
                    return Err(anyhow::anyhow!("Connection closed"));
                }
                _ => {
                    // Other message types or binary data - ignore
                }
            }
        }

        Ok(None)
    }

    pub async fn receive_config_update(&mut self) -> Result<Option<EspConfig>> {
        if let Some(websocket) = &mut self.websocket {
            // Check for config update messages
            match websocket.next().await {
                Some(Ok(Message::Text(text))) => {
                    match serde_json::from_str::<OverlayMessage>(&text) {
                        Ok(message) => {
                            if message.message_type == "config_update" {
                                // Convert individual config update to full config
                                // This is a simplified approach - real implementation would
                                // maintain a full config state and update individual fields
                                let default_config = EspConfig::default();
                                return Ok(Some(default_config));
                            }
                        }
                        Err(e) => {
                            tracing::debug!("Failed to parse config message: {}", e);
                        }
                    }
                }
                Some(Ok(Message::Close(_))) => {
                    self.connected = false;
                    return Err(anyhow::anyhow!("Connection closed"));
                }
                Some(Err(e)) => {
                    self.connected = false;
                    return Err(anyhow::anyhow!("WebSocket error: {}", e));
                }
                None => {
                    self.connected = false;
                    return Err(anyhow::anyhow!("Connection closed"));
                }
                _ => {}
            }
        }

        Ok(None)
    }

    pub async fn send_heartbeat(&mut self) -> Result<()> {
        if let Some(websocket) = &mut self.websocket {
            let heartbeat_message = OverlayMessage {
                message_type: "heartbeat".to_string(),
                data: serde_json::json!({
                    "overlay_id": "system_performance_overlay",
                    "timestamp": std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64
                }),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
            };

            let message_json = serde_json::to_string(&heartbeat_message)?;
            websocket.send(Message::Text(message_json)).await?;
            self.last_heartbeat = std::time::Instant::now();
        }

        Ok(())
    }

    pub fn get_connection_status(&self) -> ConnectionStatus {
        ConnectionStatus {
            connected: self.connected,
            last_heartbeat: self.last_heartbeat,
            helper_url: self.helper_url.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionStatus {
    pub connected: bool,
    pub last_heartbeat: std::time::Instant,
    pub helper_url: String,
}
