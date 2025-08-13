use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use winit::{
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoop},
    window::{Window, WindowBuilder},
    dpi::PhysicalSize,
};
use wgpu::util::DeviceExt;

mod renderer;
mod ipc_client;
mod esp_data;
mod overlay_ui;
mod stealth;

use renderer::Renderer;
use ipc_client::IpcClient;
use esp_data::{EspData, EspConfig};
use overlay_ui::OverlayUI;
use stealth::OverlayStealth;

#[derive(Clone)]
pub struct OverlayState {
    pub esp_data: Arc<RwLock<Option<EspData>>>,
    pub esp_config: Arc<RwLock<EspConfig>>,
    pub ipc_client: Arc<Mutex<IpcClient>>,
    pub stealth: Arc<Mutex<OverlayStealth>>,
    pub shutdown_signal: Arc<tokio::sync::Notify>,
}

fn main() -> Result<()> {
    // Initialize stealth measures immediately
    let mut stealth = OverlayStealth::new();
    stealth.initialize_overlay_stealth()?;

    // Set up logging (memory-only in production)
    setup_logging(&stealth)?;

    // Initialize tokio runtime for async operations
    let rt = tokio::runtime::Runtime::new()?;
    
    rt.block_on(async {
        run_overlay().await
    })
}

async fn run_overlay() -> Result<()> {
    tracing::info!("Starting system performance overlay...");

    // Initialize IPC client
    let ipc_client = IpcClient::new().await
        .context("Failed to initialize IPC client")?;

    // Initialize stealth manager
    let stealth = OverlayStealth::new();

    // Create overlay state
    let overlay_state = OverlayState {
        esp_data: Arc::new(RwLock::new(None)),
        esp_config: Arc::new(RwLock::new(EspConfig::default())),
        ipc_client: Arc::new(Mutex::new(ipc_client)),
        stealth: Arc::new(Mutex::new(stealth)),
        shutdown_signal: Arc::new(tokio::sync::Notify::new()),
    };

    // Start background IPC task
    let ipc_task = {
        let state = overlay_state.clone();
        tokio::spawn(async move {
            ipc_background_task(state).await;
        })
    };

    // Start stealth monitoring task
    let stealth_task = {
        let state = overlay_state.clone();
        tokio::spawn(async move {
            stealth_monitoring_task(state).await;
        })
    };

    // Initialize winit event loop and window
    let event_loop = EventLoop::new();
    let window = create_overlay_window(&event_loop)?;

    // Initialize renderer
    let mut renderer = Renderer::new(&window).await?;
    let mut overlay_ui = OverlayUI::new();

    // Main event loop
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Poll;

        match event {
            Event::WindowEvent {
                ref event,
                window_id,
            } if window_id == window.id() => {
                match event {
                    WindowEvent::CloseRequested => {
                        tracing::info!("Close requested, shutting down overlay");
                        overlay_state.shutdown_signal.notify_one();
                        *control_flow = ControlFlow::Exit;
                    }
                    WindowEvent::Resized(physical_size) => {
                        if let Err(e) = renderer.resize(*physical_size) {
                            tracing::error!("Failed to resize renderer: {}", e);
                        }
                    }
                    WindowEvent::ScaleFactorChanged { new_inner_size, .. } => {
                        if let Err(e) = renderer.resize(**new_inner_size) {
                            tracing::error!("Failed to resize renderer after scale change: {}", e);
                        }
                    }
                    _ => {}
                }
            }
            Event::RedrawRequested(window_id) if window_id == window.id() => {
                // Get current ESP data
                let esp_data = overlay_state.esp_data.try_read().ok()
                    .and_then(|data| data.clone());
                let esp_config = overlay_state.esp_config.try_read().ok()
                    .map(|config| config.clone())
                    .unwrap_or_default();

                // Update UI with current data
                overlay_ui.update(&esp_data, &esp_config);

                // Render frame
                match renderer.render(&overlay_ui) {
                    Ok(_) => {}
                    Err(wgpu::SurfaceError::Lost) => {
                        if let Err(e) = renderer.resize(renderer.get_size()) {
                            tracing::error!("Failed to recreate surface: {}", e);
                        }
                    }
                    Err(wgpu::SurfaceError::OutOfMemory) => {
                        tracing::error!("Out of memory, shutting down");
                        *control_flow = ControlFlow::Exit;
                    }
                    Err(e) => {
                        tracing::error!("Render error: {}", e);
                    }
                }
            }
            Event::MainEventsCleared => {
                // Request redraw for smooth animation
                window.request_redraw();
            }
            _ => {}
        }
    });
}

fn create_overlay_window(event_loop: &EventLoop<()>) -> Result<Window> {
    // Get primary monitor dimensions
    let primary_monitor = event_loop.primary_monitor()
        .context("No primary monitor found")?;
    let monitor_size = primary_monitor.size();

    let window = WindowBuilder::new()
        .with_title("System Performance Monitor")
        .with_inner_size(PhysicalSize::new(monitor_size.width, monitor_size.height))
        .with_decorations(false)
        .with_transparent(true)
        .with_window_level(winit::window::WindowLevel::AlwaysOnTop)
        .with_resizable(false)
        .with_maximized(false)
        .with_visible(true)
        .build(event_loop)
        .context("Failed to create overlay window")?;

    // Set window to fullscreen overlay mode
    setup_overlay_window(&window)?;

    Ok(window)
}

fn setup_overlay_window(window: &Window) -> Result<()> {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::*;
    use winit::platform::windows::WindowExtWindows;

    let hwnd = HWND(window.hwnd() as isize);

    unsafe {
        // Set window style for overlay
        let mut style = GetWindowLongW(hwnd, GWL_EXSTYLE);
        style |= WS_EX_LAYERED.0 as i32;
        style |= WS_EX_TRANSPARENT.0 as i32;
        style |= WS_EX_TOPMOST.0 as i32;
        style |= WS_EX_TOOLWINDOW.0 as i32;
        SetWindowLongW(hwnd, GWL_EXSTYLE, style);

        // Set layered window attributes for transparency
        SetLayeredWindowAttributes(hwnd, windows::Win32::Foundation::COLORREF(0), 255, LWA_ALPHA);

        // Position window to cover entire screen
        SetWindowPos(
            hwnd,
            HWND_TOPMOST,
            0, 0,
            GetSystemMetrics(SM_CXSCREEN),
            GetSystemMetrics(SM_CYSCREEN),
            SWP_SHOWWINDOW | SWP_NOACTIVATE,
        );
    }

    Ok(())
}

async fn ipc_background_task(overlay_state: OverlayState) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(16)); // ~60 FPS

    loop {
        tokio::select! {
            _ = interval.tick() => {
                // Try to receive ESP data from helper
                let mut ipc_client = overlay_state.ipc_client.lock().await;
                match ipc_client.receive_esp_data().await {
                    Ok(Some(esp_data)) => {
                        // Update shared ESP data
                        let mut data = overlay_state.esp_data.write().await;
                        *data = Some(esp_data);
                    }
                    Ok(None) => {
                        // No new data available
                    }
                    Err(e) => {
                        tracing::debug!("Failed to receive ESP data: {}", e);
                        
                        // Try to reconnect if connection lost
                        if !ipc_client.is_connected().await {
                            tracing::info!("Attempting to reconnect to helper...");
                            if let Err(e) = ipc_client.reconnect().await {
                                tracing::warn!("Failed to reconnect: {}", e);
                            }
                        }
                    }
                }

                // Try to receive config updates
                match ipc_client.receive_config_update().await {
                    Ok(Some(config)) => {
                        let mut current_config = overlay_state.esp_config.write().await;
                        *current_config = config;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::debug!("Failed to receive config update: {}", e);
                    }
                }
            }
            _ = overlay_state.shutdown_signal.notified() => {
                tracing::info!("IPC background task shutting down");
                break;
            }
        }
    }
}

async fn stealth_monitoring_task(overlay_state: OverlayState) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let mut stealth = overlay_state.stealth.lock().await;
                if !stealth.perform_stealth_checks().await {
                    tracing::warn!("Stealth check failed - initiating shutdown");
                    overlay_state.shutdown_signal.notify_one();
                    break;
                }
            }
            _ = overlay_state.shutdown_signal.notified() => {
                tracing::info!("Stealth monitoring task shutting down");
                break;
            }
        }
    }
}

fn setup_logging(stealth: &OverlayStealth) -> Result<()> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    if stealth.is_debug_mode() {
        // Debug mode - console logging
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_target(false)
                .with_thread_ids(false)
                .with_file(false)
                .with_line_number(false))
            .with(tracing_subscriber::filter::LevelFilter::DEBUG)
            .init();
    } else {
        // Production mode - memory logging only
        let memory_writer = stealth.get_memory_writer();
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_target(false)
                .with_thread_ids(false)
                .with_file(false)
                .with_line_number(false))
            .with(tracing_subscriber::filter::LevelFilter::WARN)
            .init();
    }

    Ok(())
}
