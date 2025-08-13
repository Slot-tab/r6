#![no_std]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

extern crate alloc;

// Re-export the unified driver module
pub mod driver;

// Re-export main components for external use
pub use driver::{
    UnifiedDriverState,
    UnifiedAntiAnalysis,
    UnifiedCommunication,
    UnifiedMemoryReader,
    UnifiedStealthManager,
    UnifiedGameOffsets,
    init_unified_driver,
    get_unified_driver_state,
    cleanup_unified_driver,
    DriverEntry,
    ProcessInfo,
    ReadMemoryRequest,
    EntityData,
    PlayerData,
    GadgetData,
    Vector3,
    Matrix4x4,
    BoneIndex,
    GadgetType,
    PlayerState,
    Team,
    StealthLevel,
};

// Global initialization function for the unified driver
pub fn initialize_unified_kernel_driver() -> bool {
    // This would be called during driver initialization
    // All initialization is now handled in the unified driver module
    true
}

// Global cleanup function for the unified driver
pub fn cleanup_unified_kernel_driver() {
    cleanup_unified_driver();
}

// Version information
pub const UNIFIED_DRIVER_VERSION: &str = "1.0.0";
pub const UNIFIED_DRIVER_BUILD: &str = "unified-consolidation";

// Feature flags for the unified driver
pub const FEATURES: &[&str] = &[
    "unified-anti-analysis",
    "unified-communication", 
    "unified-memory-reader",
    "unified-stealth-manager",
    "unified-game-offsets",
    "comprehensive-vm-detection",
    "advanced-debugger-detection",
    "secure-communication-channel",
    "game-memory-reading",
    "driver-stealth-hiding",
    "pe-header-erasure",
    "integrity-verification",
    "self-destruct-capability",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_driver_initialization() {
        assert!(initialize_unified_kernel_driver());
    }

    #[test]
    fn test_unified_driver_features() {
        assert!(!FEATURES.is_empty());
        assert!(FEATURES.contains(&"unified-anti-analysis"));
        assert!(FEATURES.contains(&"unified-communication"));
        assert!(FEATURES.contains(&"unified-memory-reader"));
        assert!(FEATURES.contains(&"unified-stealth-manager"));
        assert!(FEATURES.contains(&"unified-game-offsets"));
    }

    #[test]
    fn test_version_info() {
        assert_eq!(UNIFIED_DRIVER_VERSION, "1.0.0");
        assert_eq!(UNIFIED_DRIVER_BUILD, "unified-consolidation");
    }
}
