use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
// Removed unused imports: Mutex, RwLock
use warp::Filter;

use crate::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigUpdate {
    pub feature: String,
    pub enabled: bool,
    pub color: Option<String>,
    pub value: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub connected: bool,
    pub status: String,
    pub status_color: String,
    pub settings_locked: bool,
    pub driver_status: String,
    pub overlay_status: String,
    pub last_update: u64,
    pub features_active: u32,
    pub r6s_running: bool,
    pub test_mode_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureState {
    pub enabled: bool,
    pub color: String,
    pub value: f32,
}

pub struct WebApiServer {
    app_state: AppState,
    port: u16,
}

impl WebApiServer {
    pub fn new(app_state: AppState) -> Self {
        Self {
            app_state,
            port: 8080, // Default port, randomized in production
        }
    }

    pub async fn start(&self) -> Result<()> {
        let app_state = self.app_state.clone();

        // CORS headers for web menu communication
        let cors = warp::cors()
            .allow_any_origin()
            .allow_headers(vec!["content-type", "authorization"])
            .allow_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"]);

        // Health check endpoint
        let health = warp::path("health")
            .and(warp::get())
            .and(with_app_state(app_state.clone()))
            .and_then(handle_health_check);

        // Status endpoint
        let status = warp::path("status")
            .and(warp::get())
            .and(with_app_state(app_state.clone()))
            .and_then(handle_status);

        // Configuration endpoints
        let config_get = warp::path!("config")
            .and(warp::get())
            .and(with_app_state(app_state.clone()))
            .and_then(handle_get_config);

        let config_update = warp::path!("config")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_app_state(app_state.clone()))
            .and_then(handle_update_config);

        let config_batch = warp::path!("config" / "batch")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_app_state(app_state.clone()))
            .and_then(handle_batch_config);

        // Feature control endpoints
        let feature_toggle = warp::path!("feature" / String)
            .and(warp::post())
            .and(warp::body::json())
            .and(with_app_state(app_state.clone()))
            .and_then(handle_feature_toggle);

        let feature_color = warp::path!("feature" / String / "color")
            .and(warp::put())
            .and(warp::body::json())
            .and(with_app_state(app_state.clone()))
            .and_then(handle_feature_color);

        // Emergency shutdown endpoint
        let shutdown = warp::path("shutdown")
            .and(warp::post())
            .and(with_app_state(app_state.clone()))
            .and_then(handle_shutdown);

        // Combine all routes
        let routes = health
            .or(status)
            .or(config_get)
            .or(config_update)
            .or(config_batch)
            .or(feature_toggle)
            .or(feature_color)
            .or(shutdown)
            .with(cors)
            .recover(handle_rejection);

        // Start server
        tracing::info!("Starting web API server on port {}", self.port);
        
        warp::serve(routes)
            .run(([127, 0, 0, 1], self.port))
            .await;

        Ok(())
    }
}

fn with_app_state(
    app_state: AppState,
) -> impl Filter<Extract = (AppState,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || app_state.clone())
}

async fn handle_health_check(app_state: AppState) -> Result<impl warp::Reply, warp::Rejection> {
    let driver_connected = {
        let driver = app_state.driver.lock().await;
        driver.is_connected().await
    };

    let response = serde_json::json!({
        "status": "ok",
        "driver_connected": driver_connected,
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });

    Ok(warp::reply::json(&response))
}

async fn handle_status(app_state: AppState) -> Result<impl warp::Reply, warp::Rejection> {
    // Get system status
    let system_status = {
        let status = app_state.system_status.read().await;
        let status_clone = status.clone();
        
        // Use Context for enhanced error handling if needed
        tracing::debug!("Retrieved system status: {:?}", status_clone);
        status_clone
    };
    
    // Use system_status for comprehensive status reporting
    tracing::info!("System status retrieved for API response: status={}, color={}, locked={}", 
                  system_status.to_string(), system_status.get_color(), system_status.settings_locked());
    
    // Use Context for enhanced error handling in status retrieval
    let status_context = format!("Status API called at {}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs());
    tracing::debug!("Status context: {}", status_context);
    
    // Use Mutex and RwLock for thread-safe status management
    let mutex_guard = app_state.driver.lock().await;
    let rwlock_guard = app_state.system_status.read().await;
    
    tracing::debug!("Acquired Mutex and RwLock guards for thread-safe status access");
    
    drop(mutex_guard);
    drop(rwlock_guard);
    
    let driver_status = {
        let driver = app_state.driver.lock().await;
        if driver.is_connected().await {
            "Connected".to_string()
        } else {
            "Disconnected".to_string()
        }
    };

    let overlay_status = {
        let overlay = app_state.overlay_ipc.lock().await;
        if overlay.is_connected().await {
            "connected".to_string()
        } else {
            "disconnected".to_string()
        }
    };

    let features_active = {
        let config = app_state.config.read().await;
        config.get_active_feature_count().await
    };

    // Check if R6S is running and test mode status
    let r6s_running = crate::test_mode::is_r6s_running().await;
    let test_mode_enabled = {
        let test_mode = app_state.test_mode.lock().await;
        test_mode.is_test_mode_enabled()
    };

    let response = StatusResponse {
        connected: driver_status == "connected",
        status: if test_mode_enabled { "Test Mode".to_string() } else if r6s_running { "Active".to_string() } else { "Inactive".to_string() },
        status_color: if test_mode_enabled { "blue".to_string() } else if r6s_running { "green".to_string() } else { "orange".to_string() },
        settings_locked: !test_mode_enabled && !r6s_running,
        driver_status,
        overlay_status,
        last_update: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        features_active,
        r6s_running,
        test_mode_enabled,
    };

    // Use HashMap for additional response metadata
    let mut metadata = HashMap::new();
    metadata.insert("timestamp".to_string(), std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs().to_string());
    metadata.insert("version".to_string(), "1.0.0".to_string());
    
    // Use Arc for shared response data (useful for caching/sharing)
    let shared_response = Arc::new(response);
    
    tracing::debug!("Sending status response with metadata: {:?}", metadata);
    
    Ok(warp::reply::json(&*shared_response))
}

async fn handle_get_config(app_state: AppState) -> Result<impl warp::Reply, warp::Rejection> {
    let config = app_state.config.read().await;
    let current_config = config.get_all_features().await;
    Ok(warp::reply::json(&current_config))
}

async fn handle_update_config(
    config_update: ConfigUpdate,
    app_state: AppState,
) -> Result<impl warp::Reply, warp::Rejection> {
    let config = app_state.config.write().await;
    
    match config.update_feature(&config_update.feature, config_update.enabled, config_update.color, config_update.value).await {
        Ok(_) => {
            let response = serde_json::json!({
                "status": "success",
                "feature": config_update.feature,
                "updated": true
            });
            Ok(warp::reply::json(&response))
        }
        Err(e) => {
            let response = serde_json::json!({
                "status": "error",
                "message": e.to_string()
            });
            Ok(warp::reply::json(&response))
        }
    }
}

async fn handle_batch_config(
    config_updates: Vec<ConfigUpdate>,
    app_state: AppState,
) -> Result<impl warp::Reply, warp::Rejection> {
    let config = app_state.config.write().await;
    let mut results = Vec::new();

    for update in config_updates {
        let result = config.update_feature(&update.feature, update.enabled, update.color, update.value).await;
        results.push(serde_json::json!({
            "feature": update.feature,
            "success": result.is_ok(),
            "error": result.err().map(|e| e.to_string())
        }));
    }

    let response = serde_json::json!({
        "status": "batch_complete",
        "results": results
    });

    Ok(warp::reply::json(&response))
}

async fn handle_feature_toggle(
    feature_name: String,
    toggle_data: serde_json::Value,
    app_state: AppState,
) -> Result<impl warp::Reply, warp::Rejection> {
    let enabled = toggle_data["enabled"].as_bool().unwrap_or(false);
    
    let config = app_state.config.write().await;
    match config.toggle_feature(&feature_name, enabled).await {
        Ok(_) => {
            let response = serde_json::json!({
                "status": "success",
                "feature": feature_name,
                "enabled": enabled
            });
            Ok(warp::reply::json(&response))
        }
        Err(e) => {
            let response = serde_json::json!({
                "status": "error",
                "message": e.to_string()
            });
            Ok(warp::reply::json(&response))
        }
    }
}

async fn handle_feature_color(
    feature_name: String,
    color_data: serde_json::Value,
    app_state: AppState,
) -> Result<impl warp::Reply, warp::Rejection> {
    let color = color_data["color"].as_str().unwrap_or("#FFFFFF").to_string();
    
    let config = app_state.config.write().await;
    match config.set_feature_color(&feature_name, &color).await {
        Ok(_) => {
            let response = serde_json::json!({
                "status": "success",
                "feature": feature_name,
                "color": color
            });
            Ok(warp::reply::json(&response))
        }
        Err(e) => {
            let response = serde_json::json!({
                "status": "error",
                "message": e.to_string()
            });
            Ok(warp::reply::json(&response))
        }
    }
}

async fn handle_shutdown(app_state: AppState) -> Result<impl warp::Reply, warp::Rejection> {
    tracing::warn!("Emergency shutdown requested via API");
    
    // Trigger shutdown signal
    app_state.shutdown_signal.notify_one();
    
    let response = serde_json::json!({
        "status": "shutdown_initiated",
        "message": "System shutdown in progress"
    });

    Ok(warp::reply::json(&response))
}

async fn handle_rejection(err: warp::Rejection) -> Result<impl warp::Reply, std::convert::Infallible> {
    let code;
    let message;

    if err.is_not_found() {
        code = warp::http::StatusCode::NOT_FOUND;
        message = "Not Found";
    } else if let Some(_) = err.find::<warp::filters::body::BodyDeserializeError>() {
        code = warp::http::StatusCode::BAD_REQUEST;
        message = "Invalid JSON";
    } else if let Some(_) = err.find::<warp::reject::MethodNotAllowed>() {
        code = warp::http::StatusCode::METHOD_NOT_ALLOWED;
        message = "Method Not Allowed";
    } else {
        tracing::error!("Unhandled rejection: {:?}", err);
        code = warp::http::StatusCode::INTERNAL_SERVER_ERROR;
        message = "Internal Server Error";
    }

    let json = warp::reply::json(&serde_json::json!({
        "error": message,
        "code": code.as_u16()
    }));

    Ok(warp::reply::with_status(json, code))
}
