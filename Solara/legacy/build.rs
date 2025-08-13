use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Generate unique build identifiers for the overlay
    let build_id = generate_build_id();
    let overlay_key = generate_overlay_key();
    
    // Write build constants
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("overlay_constants.rs");
    
    let constants = format!(
        r#"
// Auto-generated overlay constants - DO NOT EDIT
pub const OVERLAY_BUILD_ID: u64 = 0x{:016X};
pub const OVERLAY_KEY: [u8; 32] = [{}];
pub const HELPER_IPC_PORT: u16 = {};
pub const OVERLAY_NAME: &str = "SystemPerformanceOverlay_{:08X}";
pub const WINDOW_CLASS: &str = "SystemMonitor_{:08X}";
"#,
        build_id,
        overlay_key.iter()
            .map(|b| format!("0x{:02X}", b))
            .collect::<Vec<_>>()
            .join(", "),
        8081 + ((build_id & 0xFF) as u16 % 1000), // Randomized IPC port
        (build_id & 0xFFFFFFFF) as u32,
        ((build_id >> 32) & 0xFFFFFFFF) as u32
    );
    
    fs::write(&dest_path, constants).unwrap();
    
    // Set up Windows UWP application build
    println!("cargo:rustc-link-arg=/SUBSYSTEM:WINDOWS");
    
    // Create Windows resource file for UWP compatibility
    create_resource_file();
    
    println!("cargo:rerun-if-changed=build.rs");
}

fn generate_build_id() -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};
    
    let mut hasher = DefaultHasher::new();
    
    // Hash current timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    timestamp.hash(&mut hasher);
    
    // Hash environment info for uniqueness
    if let Ok(user) = env::var("USERNAME") {
        user.hash(&mut hasher);
    }
    if let Ok(computer) = env::var("COMPUTERNAME") {
        computer.hash(&mut hasher);
    }
    
    // Add overlay-specific salt
    "SOLARA_OVERLAY_BUILD".hash(&mut hasher);
    
    hasher.finish()
}

fn generate_overlay_key() -> [u8; 32] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let build_id = generate_build_id();
    let mut key = [0u8; 32];
    
    for i in 0..4 {
        let mut hasher = DefaultHasher::new();
        build_id.hash(&mut hasher);
        i.hash(&mut hasher);
        "OVERLAY_KEY".hash(&mut hasher);
        
        let hash = hasher.finish();
        let bytes = hash.to_le_bytes();
        
        for j in 0..8 {
            if i * 8 + j < 32 {
                key[i * 8 + j] = bytes[j];
            }
        }
    }
    
    key
}

fn create_resource_file() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let resource_path = Path::new(&out_dir).join("overlay.rc");
    
    let build_id = generate_build_id();
    let version_major = (build_id >> 48) as u16;
    let version_minor = (build_id >> 32 & 0xFFFF) as u16;
    let version_patch = (build_id >> 16 & 0xFFFF) as u16;
    let version_build = (build_id & 0xFFFF) as u16;
    
    let resource_content = format!(
        r#"
#include <windows.h>

VS_VERSION_INFO VERSIONINFO
FILEVERSION {},{},{},{}
PRODUCTVERSION {},{},{},{}
FILEFLAGSMASK VS_FFI_FILEFLAGSMASK
FILEFLAGS 0x0L
FILEOS VOS_NT_WINDOWS32
FILETYPE VFT_APP
FILESUBTYPE VFT2_UNKNOWN
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904B0"
        BEGIN
            VALUE "CompanyName", "Microsoft Corporation"
            VALUE "FileDescription", "System Performance Monitor"
            VALUE "FileVersion", "{}.{}.{}.{}"
            VALUE "InternalName", "SystemMonitor"
            VALUE "LegalCopyright", "Copyright (C) Microsoft Corporation. All rights reserved."
            VALUE "OriginalFilename", "SystemMonitor.exe"
            VALUE "ProductName", "Microsoft Windows Operating System"
            VALUE "ProductVersion", "{}.{}.{}.{}"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
"#,
        version_major, version_minor, version_patch, version_build,
        version_major, version_minor, version_patch, version_build,
        version_major, version_minor, version_patch, version_build,
        version_major, version_minor, version_patch, version_build
    );
    
    fs::write(&resource_path, resource_content).unwrap();
}
