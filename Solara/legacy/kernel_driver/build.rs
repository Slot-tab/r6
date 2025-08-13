use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Generate unique build identifiers for the driver
    let build_id = generate_build_id();
    let driver_magic = generate_driver_magic();
    let communication_key = generate_communication_key();
    
    // Write build constants
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("driver_constants.rs");
    
    let constants = format!(
        r#"
// Auto-generated driver constants - DO NOT EDIT
pub const DRIVER_BUILD_ID: u64 = 0x{:016X};
pub const DRIVER_MAGIC: u32 = 0x{:08X};
pub const COMM_KEY: [u8; 32] = [{}];
pub const DEVICE_NAME: &str = "\\Device\\SystemService_{:08X}";
pub const IOCTL_BASE: u32 = 0x{:06X};
"#,
        build_id,
        driver_magic,
        communication_key.iter()
            .map(|b| format!("0x{:02X}", b))
            .collect::<Vec<_>>()
            .join(", "),
        (build_id & 0xFFFFFFFF) as u32,
        ((build_id >> 32) & 0xFFFFFF) as u32
    );
    
    fs::write(&dest_path, constants).unwrap();
    
    // Set up Windows driver build environment
    println!("cargo:rustc-link-arg=/DRIVER");
    println!("cargo:rustc-link-arg=/ENTRY:DriverEntry");
    println!("cargo:rustc-link-arg=/SUBSYSTEM:NATIVE");
    println!("cargo:rustc-link-arg=/NODEFAULTLIB");
    println!("cargo:rustc-link-arg=/MERGE:.edata=.rdata");
    println!("cargo:rustc-link-arg=/MERGE:.rustc=.data");
    println!("cargo:rustc-link-arg=/INTEGRITYCHECK");
    
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
    
    // Add driver-specific salt
    "SOLARA_DRIVER_BUILD".hash(&mut hasher);
    
    hasher.finish()
}

fn generate_driver_magic() -> u32 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    "SOLARA_DRIVER_MAGIC".hash(&mut hasher);
    generate_build_id().hash(&mut hasher);
    
    // Ensure it's not a common value
    let mut magic = hasher.finish() as u32;
    if magic == 0 || magic == 0xFFFFFFFF || magic == 0xDEADBEEF || magic == 0xCAFEBABE {
        magic = magic.wrapping_add(0x12345678);
    }
    
    magic
}

fn generate_communication_key() -> [u8; 32] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let build_id = generate_build_id();
    let mut key = [0u8; 32];
    
    for i in 0..4 {
        let mut hasher = DefaultHasher::new();
        build_id.hash(&mut hasher);
        i.hash(&mut hasher);
        "DRIVER_COMM_KEY".hash(&mut hasher);
        
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
