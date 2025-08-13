use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::cell::UnsafeCell;
use std::ffi::CString;
use std::ptr;
use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::ioapiset::DeviceIoControl;
use winapi::um::winnt::{FILE_ATTRIBUTE_NORMAL, GENERIC_READ, GENERIC_WRITE, HANDLE};
use winapi::shared::winerror::ERROR_SUCCESS;

// ESP data structures matching web menu features
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

// Driver communication structures
#[repr(C)]
struct ReadMemoryRequest {
    target_process: HANDLE,
    address: u64,
    size: usize,
}

#[repr(C)]
struct ProcessInfo {
    process_id: u32,
    base_address: u64,
    image_size: u32,
    name: [u8; 16],
}

#[repr(C)]
struct ConnectionInfo {
    driver_version: u32,
    build_signature: u64,
    status: u32,
    capabilities: u32,
}

pub struct DriverInterface {
    device_handle: HANDLE,
    connected: bool,
    last_heartbeat: UnsafeCell<std::time::Instant>,
    build_signature: u64,
    ioctl_codes: IoctlCodes,
}

// SAFETY: DriverInterface is safe to send between threads as long as
// the HANDLE is properly managed and not accessed concurrently
unsafe impl Send for DriverInterface {}
unsafe impl Sync for DriverInterface {}

struct IoctlCodes {
    read_memory: u32,
    get_process_info: u32,
    verify_connection: u32,
}

impl DriverInterface {
    pub async fn new() -> Result<Self> {
        let mut interface = Self {
            device_handle: INVALID_HANDLE_VALUE,
            connected: false,
            last_heartbeat: UnsafeCell::new(std::time::Instant::now()),
            build_signature: 0,
            ioctl_codes: IoctlCodes {
                read_memory: 0x22E004,    // Randomized IOCTL codes
                get_process_info: 0x22E008,
                verify_connection: 0x22E00C,
            },
        };

        interface.connect().await?;
        Ok(interface)
    }

    /// Create a mock driver interface for test mode (no actual driver required)
    pub async fn new_mock() -> Result<Self> {
        tracing::info!("Creating mock driver interface for test mode");
        
        let interface = Self {
            device_handle: INVALID_HANDLE_VALUE, // No real handle needed in test mode
            connected: true, // Always connected in test mode
            last_heartbeat: UnsafeCell::new(std::time::Instant::now()),
            build_signature: 0xDEADBEEF, // Mock signature
            ioctl_codes: IoctlCodes {
                read_memory: 0x22E004,
                get_process_info: 0x22E008,
                verify_connection: 0x22E00C,
            },
        };

        tracing::info!("Mock driver interface created successfully");
        Ok(interface)
    }

    async fn connect(&mut self) -> Result<()> {
        // Try multiple device names (randomized per build)
        let device_names = [
            "\\\\.\\SystemService_A1B2C3D4",
            "\\\\.\\HardwareManager_E5F6G7H8",
            "\\\\.\\PlatformDriver_I9J0K1L2",
        ];

        for device_name in &device_names {
            let device_name_cstr = CString::new(*device_name)
                .context("Failed to create device name CString")?;

            unsafe {
                let handle = CreateFileA(
                    device_name_cstr.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    ptr::null_mut(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    ptr::null_mut(),
                );

                if handle != INVALID_HANDLE_VALUE {
                    self.device_handle = handle;
                    break;
                }
            }
        }

        if self.device_handle == INVALID_HANDLE_VALUE {
            return Err(anyhow::anyhow!("Failed to open driver device"));
        }

        // Verify connection with driver
        self.verify_connection().await?;
        self.connected = true;

        Ok(())
    }

    async fn verify_connection(&mut self) -> Result<()> {
        let mut conn_info = ConnectionInfo {
            driver_version: 0,
            build_signature: 0,
            status: 0,
            capabilities: 0,
        };

        let success = unsafe {
            let mut bytes_returned = 0u32;
            DeviceIoControl(
                self.device_handle,
                self.ioctl_codes.verify_connection,
                ptr::null_mut(),
                0,
                &mut conn_info as *mut _ as *mut _,
                std::mem::size_of::<ConnectionInfo>() as u32,
                &mut bytes_returned,
                ptr::null_mut(),
            ) != 0
        };

        if !success {
            return Err(anyhow::anyhow!("Driver connection verification failed"));
        }

        if conn_info.status != 1 {
            return Err(anyhow::anyhow!("Driver not ready (status: {})", conn_info.status));
        }

        self.build_signature = conn_info.build_signature;
        Ok(())
    }

    pub async fn send_heartbeat(&self) -> Result<()> {
        if !self.connected {
            return Err(anyhow::anyhow!("Driver not connected"));
        }

        // Check last_heartbeat field to determine if heartbeat is needed
        let time_since_last_heartbeat = unsafe { (*self.last_heartbeat.get()).elapsed() };
        if time_since_last_heartbeat < std::time::Duration::from_secs(5) {
            tracing::trace!("Heartbeat not needed yet, last heartbeat was {}ms ago", 
                           time_since_last_heartbeat.as_millis());
            return Ok(());
        }

        tracing::debug!("Sending heartbeat to driver ({}s since last heartbeat)", 
                       time_since_last_heartbeat.as_secs());
        
        let mut connection_info = ConnectionInfo {
            driver_version: 1,
            build_signature: self.build_signature,
            status: 1,
            capabilities: 0xFFFFFFFF,
        };

        let mut bytes_returned: u32 = 0;
        let result = unsafe {
            DeviceIoControl(
                self.device_handle,
                self.ioctl_codes.verify_connection,
                &mut connection_info as *mut _ as *mut _,
                std::mem::size_of::<ConnectionInfo>() as u32,
                &mut connection_info as *mut _ as *mut _,
                std::mem::size_of::<ConnectionInfo>() as u32,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };

        if result == 0 || unsafe { winapi::um::errhandlingapi::GetLastError() } != ERROR_SUCCESS {
            let error_code = unsafe { winapi::um::errhandlingapi::GetLastError() };
            tracing::error!("IOCTL failed with error code: 0x{:x} (expected SUCCESS: 0x{:x})", 
                           error_code, ERROR_SUCCESS);
            return Err(anyhow::anyhow!("Failed to send IOCTL to driver"));
        }

        // Update last_heartbeat field after successful heartbeat
        // SAFETY: We use UnsafeCell for interior mutability, which is safe for single-threaded access
        unsafe {
            *self.last_heartbeat.get() = std::time::Instant::now();
        }

        tracing::trace!("Heartbeat successful, driver version: {} (heartbeat timestamp updated)", 
                       connection_info.driver_version);
        Ok(())
    }

    pub async fn is_connected(&self) -> bool {
        self.connected && self.device_handle != INVALID_HANDLE_VALUE
    }

    pub async fn get_esp_data(&self) -> Result<EspData> {
        if !self.connected {
            return Err(anyhow::anyhow!("Driver not connected"));
        }

        // Get process information first
        let process_info = self.get_process_info().await?;
        
        // Use the process info for driver communication validation
        tracing::debug!("Using process info for driver validation: PID={}, Base=0x{:x}, Size={}",
                       process_info.process_id, process_info.base_address, process_info.image_size);
        
        // Validate process integrity before driver operations
        if process_info.process_id == 0 {
            return Err(anyhow::anyhow!("Invalid process ID in process info"));
        }

        // Read ESP data from game memory
        let mut esp_data = EspData {
            players: Vec::new(),
            gadgets: Vec::new(),
            objectives: Vec::new(),
            game_state: GameState {
                game_mode: 0,
                round_state: 0,
                bomb_planted: false,
                bomb_timer: None,
                spectator_count: 0,
            },
        };

        // Read player data (using placeholder offsets)
        for i in 0..10 { // Max 10 players
            if let Ok(player_data) = self.read_player_data(i).await {
                esp_data.players.push(player_data);
            }
        }

        // Read gadget data
        for i in 0..50 { // Max 50 gadgets
            if let Ok(gadget_data) = self.read_gadget_data(i).await {
                esp_data.gadgets.push(gadget_data);
            }
        }

        // Read objective data
        if let Ok(objective_data) = self.read_objective_data().await {
            esp_data.objectives.push(objective_data);
        }

        // Read game state
        esp_data.game_state = self.read_game_state().await?;

        Ok(esp_data)
    }

    async fn get_process_info(&self) -> Result<ProcessInfo> {
        let mut process_info = ProcessInfo {
            process_id: 0,
            base_address: 0,
            image_size: 0,
            name: [0; 16],
        };

        let success = unsafe {
            let mut bytes_returned = 0u32;
            DeviceIoControl(
                self.device_handle,
                self.ioctl_codes.get_process_info,
                ptr::null_mut(),
                0,
                &mut process_info as *mut _ as *mut _,
                std::mem::size_of::<ProcessInfo>() as u32,
                &mut bytes_returned,
                ptr::null_mut(),
            ) != 0
        };

        if !success {
            return Err(anyhow::anyhow!("Failed to get process info"));
        }

        Ok(process_info)
    }

    async fn read_memory(&self, address: u64, size: usize) -> Result<Vec<u8>> {
        let request = ReadMemoryRequest {
            target_process: ptr::null_mut(),
            address,
            size,
        };

        let mut buffer = vec![0u8; size];
        let mut bytes_returned = 0u32;

        let success = unsafe {
            DeviceIoControl(
                self.device_handle,
                self.ioctl_codes.read_memory,
                &request as *const _ as *mut _,
                std::mem::size_of::<ReadMemoryRequest>() as u32,
                buffer.as_mut_ptr() as *mut _,
                size as u32,
                &mut bytes_returned,
                ptr::null_mut(),
            ) != 0
        };

        if !success {
            return Err(anyhow::anyhow!("Memory read failed"));
        }

        buffer.truncate(bytes_returned as usize);
        Ok(buffer)
    }

    async fn read_player_data(&self, player_index: u32) -> Result<PlayerData> {
        // PLACEHOLDER IMPLEMENTATION - Uses fake offsets
        // Real implementation would use actual game offsets

        let base_address = 0x140000000u64; // Placeholder base address
        let entity_list_offset = 0xDEADBEEF; // Placeholder offset
        let entity_size = 0x1000; // Placeholder entity size

        let entity_address = base_address + entity_list_offset + (player_index as u64 * entity_size);

        // Read player health (placeholder)
        let health_data = self.read_memory(entity_address + 0x100, 4).await?;
        let health = if health_data.len() >= 4 {
            u32::from_le_bytes([health_data[0], health_data[1], health_data[2], health_data[3]])
        } else {
            100 // Default health
        };

        // Read player position (placeholder)
        let position_data = self.read_memory(entity_address + 0x200, 12).await?;
        let position = if position_data.len() >= 12 {
            Vector3 {
                x: f32::from_le_bytes([position_data[0], position_data[1], position_data[2], position_data[3]]),
                y: f32::from_le_bytes([position_data[4], position_data[5], position_data[6], position_data[7]]),
                z: f32::from_le_bytes([position_data[8], position_data[9], position_data[10], position_data[11]]),
            }
        } else {
            Vector3 { x: 0.0, y: 0.0, z: 0.0 }
        };

        // Read team (placeholder)
        let team_data = self.read_memory(entity_address + 0x300, 4).await?;
        let team = if team_data.len() >= 4 {
            let team_id = u32::from_le_bytes([team_data[0], team_data[1], team_data[2], team_data[3]]);
            match team_id {
                0 => Team::Attackers,
                1 => Team::Defenders,
                _ => Team::Spectator,
            }
        } else {
            Team::Spectator
        };

        Ok(PlayerData {
            entity_id: player_index,
            position,
            health,
            team,
            name: format!("Player_{}", player_index),
            operator_id: 0,
            state: PlayerState::Alive,
            bones: Vec::new(), // Would read bone data here
            distance: 0.0,
            visible: true,
        })
    }

    async fn read_gadget_data(&self, gadget_index: u32) -> Result<GadgetData> {
        // PLACEHOLDER IMPLEMENTATION
        let base_address = 0x140000000u64;
        let gadget_list_offset = 0xCAFEBABE;
        let gadget_size = 0x200;

        let gadget_address = base_address + gadget_list_offset + (gadget_index as u64 * gadget_size);

        // Read gadget type (placeholder)
        let type_data = self.read_memory(gadget_address + 0x10, 4).await?;
        let gadget_type = if type_data.len() >= 4 {
            let type_id = u32::from_le_bytes([type_data[0], type_data[1], type_data[2], type_data[3]]);
            match type_id {
                1 => GadgetType::Trap,
                2 => GadgetType::Camera,
                3 => GadgetType::Drone,
                4 => GadgetType::Destructible,
                5 => GadgetType::Breaching,
                6 => GadgetType::Throwable,
                7 => GadgetType::Utility,
                _ => GadgetType::Unknown,
            }
        } else {
            GadgetType::Unknown
        };

        // Read position (placeholder)
        let position_data = self.read_memory(gadget_address + 0x20, 12).await?;
        let position = if position_data.len() >= 12 {
            Vector3 {
                x: f32::from_le_bytes([position_data[0], position_data[1], position_data[2], position_data[3]]),
                y: f32::from_le_bytes([position_data[4], position_data[5], position_data[6], position_data[7]]),
                z: f32::from_le_bytes([position_data[8], position_data[9], position_data[10], position_data[11]]),
            }
        } else {
            Vector3 { x: 0.0, y: 0.0, z: 0.0 }
        };

        Ok(GadgetData {
            gadget_id: gadget_index,
            gadget_type,
            position,
            owner_id: 0,
            state: 1,
            distance: 0.0,
        })
    }

    async fn read_objective_data(&self) -> Result<ObjectiveData> {
        // PLACEHOLDER IMPLEMENTATION
        Ok(ObjectiveData {
            objective_type: ObjectiveType::Bomb,
            position: Vector3 { x: 0.0, y: 0.0, z: 0.0 },
            state: 0,
            timer: None,
        })
    }

    async fn read_game_state(&self) -> Result<GameState> {
        // PLACEHOLDER IMPLEMENTATION
        Ok(GameState {
            game_mode: 1,
            round_state: 1,
            bomb_planted: false,
            bomb_timer: None,
            spectator_count: 0,
        })
    }

    pub async fn read_string_from_memory(&self, address: u64, max_length: usize) -> Result<String> {
        // Read string from memory at the specified address
        tracing::debug!("Reading string from memory at address: 0x{:X}, max_length: {}", address, max_length);
        
        // Check if address is valid
        if address == 0 || address < 0x10000 {
            return Err(anyhow::anyhow!("Invalid memory address: 0x{:X}", address));
        }
        
        // In test mode, return simulated player names
        if std::env::var("SOLARA_TEST_MODE").is_ok() {
            let test_names = vec!["Player1", "Spectator2", "Observer3", "Viewer4"];
            let index = (address % test_names.len() as u64) as usize;
            return Ok(test_names[index].to_string());
        }
        
        // Read memory buffer
        let mut buffer = vec![0u8; max_length];
        let bytes_read = self.read_memory(address, max_length).await?;
        
        if bytes_read.is_empty() {
            return Err(anyhow::anyhow!("Failed to read memory at address: 0x{:X}", address));
        }
        
        // Find null terminator
        let null_pos = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
        buffer.truncate(null_pos);
        
        // Convert to string, handling UTF-8 and UTF-16
        if buffer.len() >= 2 && buffer[1] == 0 {
            // Likely UTF-16 string
            let utf16_data: Vec<u16> = buffer
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect();
            String::from_utf16(&utf16_data)
                .map_err(|e| anyhow::anyhow!("UTF-16 conversion error: {}", e))
        } else {
            // UTF-8 string
            String::from_utf8(buffer)
                .map_err(|e| anyhow::anyhow!("UTF-8 conversion error: {}", e))
        }
    }

    pub fn get_local_player_team_id(&self) -> Result<u32> {
        // Get the local player's team ID
        tracing::debug!("Getting local player team ID");
        
        // In test mode, return a simulated team ID
        if std::env::var("SOLARA_TEST_MODE").is_ok() {
            return Ok(1); // Team 1 (Attackers)
        }
        
        // This would read the local player's team ID from memory
        // For now, return a placeholder value
        Ok(1) // Default to team 1
    }
}

impl Drop for DriverInterface {
    fn drop(&mut self) {
        if self.device_handle != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.device_handle);
            }
        }
    }
}
