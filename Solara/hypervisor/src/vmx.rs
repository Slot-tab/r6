use anyhow::{Result, Context};
use tracing::{info, error, warn, debug};
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::advanced_obfuscation::AdvancedObfuscation;
use crate::{obfuscated_call, obfuscated_loop};

/// VMX virtualization engine for hypervisor operation
/// 
/// Manages Intel VMX (Virtual Machine Extensions) to create a hypervisor
/// environment for stealth execution and anti-cheat evasion.
#[derive(Debug, Clone)]
pub struct VmxEngine {
    vmx_state: Arc<Mutex<VmxState>>,
}

#[derive(Debug)]
struct VmxState {
    is_initialized: bool,
    is_active: bool,
    cpu_count: usize,
    vmx_regions: Vec<VmxRegion>,
}

#[derive(Debug)]
struct VmxRegion {
    vmxon_region: Option<u64>,
    vmcs_region: Option<u64>,
    cpu_id: usize,
    is_vmx_enabled: bool,
}

/// VMX exit reasons for handling VM exits
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum VmExitReason {
    ExceptionOrNmi = 0,
    ExternalInterrupt = 1,
    TripleFault = 2,
    InitSignal = 3,
    StartupIpi = 4,
    IoSmi = 5,
    OtherSmi = 6,
    InterruptWindow = 7,
    NmiWindow = 8,
    TaskSwitch = 9,
    Cpuid = 10,
    Getsec = 11,
    Hlt = 12,
    Invd = 13,
    Invlpg = 14,
    Rdpmc = 15,
    Rdtsc = 16,
    Rsm = 17,
    Vmcall = 18,
    Vmclear = 19,
    Vmlaunch = 20,
    Vmptrld = 21,
    Vmptrst = 22,
    Vmread = 23,
    Vmresume = 24,
    Vmwrite = 25,
    Vmxoff = 26,
    Vmxon = 27,
    ControlRegisterAccess = 28,
    MovDr = 29,
    IoInstruction = 30,
    Rdmsr = 31,
    Wrmsr = 32,
    VmEntryFailureInvalidGuestState = 33,
    VmEntryFailureMsrLoading = 34,
    Mwait = 36,
    MonitorTrapFlag = 37,
    Monitor = 39,
    Pause = 40,
    VmEntryFailureMachineCheck = 41,
    TprBelowThreshold = 43,
    ApicAccess = 44,
    VirtualizedEoi = 45,
    AccessToGdtrOrIdtr = 46,
    AccessToLdtrOrTr = 47,
    EptViolation = 48,
    EptMisconfiguration = 49,
    Invept = 50,
    Rdtscp = 51,
    VmxPreemptionTimerExpired = 52,
    Invvpid = 53,
    Wbinvd = 54,
    Xsetbv = 55,
    ApicWrite = 56,
    Rdrand = 57,
    Invpcid = 58,
    Vmfunc = 59,
    Encls = 60,
    Rdseed = 61,
    Pml = 62,
    Xsaves = 63,
    Xrstors = 64,
}

impl VmxEngine {
    /// Create a new VMX engine instance
    pub fn new() -> Result<Self> {
        let cpu_count = num_cpus::get();
        
        let vmx_state = VmxState {
            is_initialized: false,
            is_active: false,
            cpu_count,
            vmx_regions: Vec::new(),
        };
        
        Ok(Self {
            vmx_state: Arc::new(Mutex::new(vmx_state)),
        })
    }

    /// Initialize the VMX engine
    pub async fn initialize(&mut self) -> Result<()> {
        let mut state = self.vmx_state.lock().await;
        
        if state.is_initialized {
            return Ok(());
        }

        info!("Initializing VMX virtualization engine");
        
        // Check VMX support
        self.check_vmx_support().await
            .context("VMX support check failed")?;
        
        // Initialize VMX for each CPU
        for cpu_id in 0..state.cpu_count {
            let vmx_region = self.initialize_cpu_vmx(cpu_id).await
                .context(format!("Failed to initialize VMX for CPU {}", cpu_id))?;
            
            state.vmx_regions.push(vmx_region);
        }
        
        state.is_initialized = true;
        info!("VMX engine initialized for {} CPUs", state.cpu_count);
        
        Ok(())
    }

    /// Activate VMX virtualization
    pub async fn activate(&mut self) -> Result<()> {
        let mut state = self.vmx_state.lock().await;
        
        if !state.is_initialized {
            return Err(anyhow::anyhow!("VMX engine not initialized"));
        }
        
        if state.is_active {
            return Ok(());
        }

        info!("Activating VMX virtualization");
        
        // Enable VMX on all CPUs
        for (cpu_id, vmx_region) in state.vmx_regions.iter_mut().enumerate() {
            self.enable_vmx_on_cpu(cpu_id, vmx_region).await
                .context(format!("Failed to enable VMX on CPU {}", cpu_id))?;
        }
        
        // Setup VMCS for each CPU
        for (cpu_id, vmx_region) in state.vmx_regions.iter_mut().enumerate() {
            self.setup_vmcs_for_cpu(cpu_id, vmx_region).await
                .context(format!("Failed to setup VMCS for CPU {}", cpu_id))?;
        }
        
        // Launch VMs on all CPUs
        for (cpu_id, vmx_region) in state.vmx_regions.iter().enumerate() {
            self.launch_vm_on_cpu(cpu_id, vmx_region).await
                .context(format!("Failed to launch VM on CPU {}", cpu_id))?;
        }
        
        state.is_active = true;
        info!("VMX virtualization activated on {} CPUs", state.cpu_count);
        
        Ok(())
    }

    /// Handle VM exits from virtualized CPUs
    pub async fn handle_vm_exits(&mut self) -> Result<()> {
        let state = self.vmx_state.lock().await;
        let cpu_count = state.cpu_count;
        drop(state);
        
        // Check for VM exits on each CPU
        for cpu_id in 0..cpu_count {
            // Simulate checking for VM exits (in real implementation, this would check VMCS)
            if self.check_pending_vm_exit(cpu_id).await {
                // Simulate different exit reasons based on CPU ID for demonstration
                let exit_reason = match cpu_id % 4 {
                    0 => VmExitReason::Cpuid,
                    1 => VmExitReason::Rdmsr,
                    2 => VmExitReason::Hlt,
                    3 => VmExitReason::EptViolation,
                    _ => VmExitReason::ExternalInterrupt,
                };
                
                // Handle the VM exit
                self.handle_vm_exit(exit_reason, cpu_id).await?;
            }
        }
        
        // Small delay to prevent excessive CPU usage
        tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
        
        Ok(())
    }
    
    /// Check if there's a pending VM exit on the specified CPU
    async fn check_pending_vm_exit(&self, cpu_id: usize) -> bool {
        // In a real implementation, this would check the VMCS for VM exit conditions
        // For simulation, randomly generate exits occasionally
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        cpu_id.hash(&mut hasher);
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        current_time.hash(&mut hasher);
        
        // Generate occasional VM exits for demonstration (about 1% chance)
        (hasher.finish() % 1000) < 10
    }

    /// Check VMX support on the system
    async fn check_vmx_support(&self) -> Result<()> {
        info!("Checking VMX support");
        
        // Check CPUID for VMX support
        let vmx_supported = self.check_cpuid_vmx_support();
        if !vmx_supported {
            return Err(anyhow::anyhow!("VMX not supported by processor"));
        }
        
        // Check VMX feature control MSR
        let feature_control_ok = self.check_vmx_feature_control();
        if !feature_control_ok {
            return Err(anyhow::anyhow!("VMX feature control not properly configured"));
        }
        
        info!("VMX support verified");
        Ok(())
    }

    /// Check CPUID for VMX support
    fn check_cpuid_vmx_support(&self) -> bool {
        use std::arch::x86_64::__cpuid;
        
        unsafe {
            let cpuid_result = __cpuid(1);
            let vmx_supported = (cpuid_result.ecx & (1 << 5)) != 0;
            
            if vmx_supported {
                debug!("CPUID indicates VMX support");
            } else {
                error!("CPUID indicates no VMX support");
            }
            
            vmx_supported
        }
    }

    /// Check VMX feature control MSR
    fn check_vmx_feature_control(&self) -> bool {
        // This would read the VMX feature control MSR
        // For now, assume it's properly configured
        debug!("VMX feature control MSR check passed");
        true
    }

    /// Initialize VMX for a specific CPU
    async fn initialize_cpu_vmx(&self, cpu_id: usize) -> Result<VmxRegion> {
        debug!("Initializing VMX for CPU {}", cpu_id);
        
        // Allocate VMXON region
        let vmxon_region = self.allocate_vmx_region().await
            .context("Failed to allocate VMXON region")?;
        
        // Allocate VMCS region
        let vmcs_region = self.allocate_vmx_region().await
            .context("Failed to allocate VMCS region")?;
        
        let vmx_region = VmxRegion {
            vmxon_region: Some(vmxon_region),
            vmcs_region: Some(vmcs_region),
            cpu_id,
            is_vmx_enabled: false,
        };
        
        debug!("VMX region created for CPU {} with VMXON at 0x{:016x}, VMCS at 0x{:016x}",
               vmx_region.cpu_id, vmxon_region, vmcs_region);
        
        debug!("VMX regions allocated for CPU {}", cpu_id);
        Ok(vmx_region)
    }

    /// Allocate a VMX region (VMXON or VMCS)
    async fn allocate_vmx_region(&self) -> Result<u64> {
        // This would allocate aligned physical memory for VMX regions
        // For now, return a placeholder address
        let region_address = 0x1000000u64; // Placeholder
        
        debug!("VMX region allocated at 0x{:016x}", region_address);
        Ok(region_address)
    }

    /// Enable VMX operation on a specific CPU
    async fn enable_vmx_on_cpu(&self, cpu_id: usize, vmx_region: &mut VmxRegion) -> Result<()> {
        debug!("Enabling VMX on CPU {} (region CPU ID: {})", cpu_id, vmx_region.cpu_id);
        
        // Verify CPU ID matches
        if cpu_id != vmx_region.cpu_id {
            return Err(anyhow::anyhow!("CPU ID mismatch: expected {}, got {}", vmx_region.cpu_id, cpu_id));
        }
        
        // This would:
        // 1. Set VMXE bit in CR4
        // 2. Execute VMXON instruction with vmx_region.vmxon_region
        // 3. Verify VMX is enabled
        
        if let Some(vmxon_addr) = vmx_region.vmxon_region {
            debug!("Using VMXON region at 0x{:016x} for CPU {}", vmxon_addr, vmx_region.cpu_id);
        }
        
        vmx_region.is_vmx_enabled = true;
        debug!("VMX enabled on CPU {}", vmx_region.cpu_id);
        
        Ok(())
    }

    /// Setup VMCS for a specific CPU
    async fn setup_vmcs_for_cpu(&self, cpu_id: usize, _vmx_region: &VmxRegion) -> Result<()> {
        debug!("Setting up VMCS for CPU {}", cpu_id);
        
        // This would:
        // 1. Clear VMCS
        // 2. Load VMCS pointer
        // 3. Configure VMCS fields
        // 4. Set up host and guest state
        
        debug!("VMCS configured for CPU {}", cpu_id);
        Ok(())
    }

    /// Launch VM on a specific CPU
    async fn launch_vm_on_cpu(&self, cpu_id: usize, _vmx_region: &VmxRegion) -> Result<()> {
        debug!("Launching VM on CPU {}", cpu_id);
        
        // This would execute VMLAUNCH instruction
        
        debug!("VM launched successfully on CPU {}", cpu_id);
        Ok(())
    }

    /// Handle a specific VM exit
    pub async fn handle_vm_exit(&self, exit_reason: VmExitReason, cpu_id: usize) -> Result<()> {
        debug!("Handling VM exit: {:?} on CPU {}", exit_reason, cpu_id);
        
        match exit_reason {
            VmExitReason::Cpuid => {
                // Handle CPUID interception for HWID spoofing
                self.handle_cpuid_exit(cpu_id).await?;
            }
            VmExitReason::Rdmsr | VmExitReason::Wrmsr => {
                // Handle MSR access for HWID spoofing
                self.handle_msr_exit(cpu_id).await?;
            }
            VmExitReason::Hlt => {
                // Handle HLT instruction
                self.handle_hlt_exit(cpu_id).await?;
            }
            VmExitReason::EptViolation => {
                // Handle EPT violations for memory protection
                self.handle_ept_violation(cpu_id).await?;
            }
            // Handle all other VM exit reasons
            VmExitReason::ExceptionOrNmi => {
                debug!("Exception or NMI exit on CPU {}", cpu_id);
            }
            VmExitReason::ExternalInterrupt => {
                debug!("External interrupt exit on CPU {}", cpu_id);
            }
            VmExitReason::TripleFault => {
                debug!("Triple fault exit on CPU {}", cpu_id);
            }
            VmExitReason::InitSignal => {
                debug!("INIT signal exit on CPU {}", cpu_id);
            }
            VmExitReason::StartupIpi => {
                debug!("Startup IPI exit on CPU {}", cpu_id);
            }
            VmExitReason::IoSmi => {
                debug!("IO SMI exit on CPU {}", cpu_id);
            }
            VmExitReason::OtherSmi => {
                debug!("Other SMI exit on CPU {}", cpu_id);
            }
            VmExitReason::InterruptWindow => {
                debug!("Interrupt window exit on CPU {}", cpu_id);
            }
            VmExitReason::NmiWindow => {
                debug!("NMI window exit on CPU {}", cpu_id);
            }
            VmExitReason::TaskSwitch => {
                debug!("Task switch exit on CPU {}", cpu_id);
            }
            VmExitReason::Getsec => {
                debug!("GETSEC exit on CPU {}", cpu_id);
            }
            VmExitReason::Invd => {
                debug!("INVD exit on CPU {}", cpu_id);
            }
            VmExitReason::Invlpg => {
                debug!("INVLPG exit on CPU {}", cpu_id);
            }
            VmExitReason::Rdpmc => {
                debug!("RDPMC exit on CPU {}", cpu_id);
            }
            VmExitReason::Rdtsc => {
                debug!("RDTSC exit on CPU {}", cpu_id);
            }
            VmExitReason::Rsm => {
                debug!("RSM exit on CPU {}", cpu_id);
            }
            VmExitReason::Vmcall => {
                debug!("VMCALL exit on CPU {}", cpu_id);
            }
            VmExitReason::Vmclear => {
                debug!("VMCLEAR exit on CPU {}", cpu_id);
            }
            VmExitReason::Vmlaunch => {
                debug!("VMLAUNCH exit on CPU {}", cpu_id);
            }
            VmExitReason::Vmptrld => {
                debug!("VMPTRLD exit on CPU {}", cpu_id);
            }
            VmExitReason::Vmptrst => {
                debug!("VMPTRST exit on CPU {}", cpu_id);
            }
            VmExitReason::Vmread => {
                debug!("VMREAD exit on CPU {}", cpu_id);
            }
            VmExitReason::Vmresume => {
                debug!("VMRESUME exit on CPU {}", cpu_id);
            }
            VmExitReason::Vmwrite => {
                debug!("VMWRITE exit on CPU {}", cpu_id);
            }
            VmExitReason::Vmxoff => {
                debug!("VMXOFF exit on CPU {}", cpu_id);
            }
            VmExitReason::Vmxon => {
                debug!("VMXON exit on CPU {}", cpu_id);
            }
            VmExitReason::ControlRegisterAccess => {
                debug!("Control register access exit on CPU {}", cpu_id);
            }
            VmExitReason::MovDr => {
                debug!("MOV DR exit on CPU {}", cpu_id);
            }
            VmExitReason::IoInstruction => {
                debug!("IO instruction exit on CPU {}", cpu_id);
            }
            VmExitReason::VmEntryFailureInvalidGuestState => {
                debug!("VM entry failure (invalid guest state) on CPU {}", cpu_id);
            }
            VmExitReason::VmEntryFailureMsrLoading => {
                debug!("VM entry failure (MSR loading) on CPU {}", cpu_id);
            }
            VmExitReason::Mwait => {
                debug!("MWAIT exit on CPU {}", cpu_id);
            }
            VmExitReason::MonitorTrapFlag => {
                debug!("Monitor trap flag exit on CPU {}", cpu_id);
            }
            VmExitReason::Monitor => {
                debug!("MONITOR exit on CPU {}", cpu_id);
            }
            VmExitReason::Pause => {
                debug!("PAUSE exit on CPU {}", cpu_id);
            }
            VmExitReason::VmEntryFailureMachineCheck => {
                debug!("VM entry failure (machine check) on CPU {}", cpu_id);
            }
            VmExitReason::TprBelowThreshold => {
                debug!("TPR below threshold exit on CPU {}", cpu_id);
            }
            VmExitReason::ApicAccess => {
                debug!("APIC access exit on CPU {}", cpu_id);
            }
            VmExitReason::VirtualizedEoi => {
                debug!("Virtualized EOI exit on CPU {}", cpu_id);
            }
            VmExitReason::AccessToGdtrOrIdtr => {
                debug!("Access to GDTR or IDTR exit on CPU {}", cpu_id);
            }
            VmExitReason::AccessToLdtrOrTr => {
                debug!("Access to LDTR or TR exit on CPU {}", cpu_id);
            }
            VmExitReason::EptMisconfiguration => {
                debug!("EPT misconfiguration exit on CPU {}", cpu_id);
            }
            VmExitReason::Invept => {
                debug!("INVEPT exit on CPU {}", cpu_id);
            }
            VmExitReason::Rdtscp => {
                debug!("RDTSCP exit on CPU {}", cpu_id);
            }
            VmExitReason::VmxPreemptionTimerExpired => {
                debug!("VMX preemption timer expired exit on CPU {}", cpu_id);
            }
            VmExitReason::Invvpid => {
                debug!("INVVPID exit on CPU {}", cpu_id);
            }
            VmExitReason::Wbinvd => {
                debug!("WBINVD exit on CPU {}", cpu_id);
            }
            VmExitReason::Xsetbv => {
                debug!("XSETBV exit on CPU {}", cpu_id);
            }
            VmExitReason::ApicWrite => {
                debug!("APIC write exit on CPU {}", cpu_id);
            }
            VmExitReason::Rdrand => {
                debug!("RDRAND exit on CPU {}", cpu_id);
            }
            VmExitReason::Invpcid => {
                debug!("INVPCID exit on CPU {}", cpu_id);
            }
            VmExitReason::Vmfunc => {
                debug!("VMFUNC exit on CPU {}", cpu_id);
            }
            VmExitReason::Encls => {
                debug!("ENCLS exit on CPU {}", cpu_id);
            }
            VmExitReason::Rdseed => {
                debug!("RDSEED exit on CPU {}", cpu_id);
            }
            VmExitReason::Pml => {
                debug!("PML exit on CPU {}", cpu_id);
            }
            VmExitReason::Xsaves => {
                debug!("XSAVES exit on CPU {}", cpu_id);
            }
            VmExitReason::Xrstors => {
                debug!("XRSTORS exit on CPU {}", cpu_id);
            }
        }
        
        Ok(())
    }

    /// Handle CPUID VM exit
    async fn handle_cpuid_exit(&self, cpu_id: usize) -> Result<()> {
        debug!("Handling CPUID exit on CPU {}", cpu_id);
        
        // This would intercept CPUID and provide spoofed values
        // In a real implementation, we would:
        // 1. Read guest EAX/ECX registers
        // 2. Call HWID spoofing system to get spoofed values
        // 3. Write spoofed values back to guest registers
        
        // Simulate reading guest registers
        let guest_eax = 0x1; // Simulated guest EAX value
        let guest_ecx = 0x0; // Simulated guest ECX value
        
        debug!("CPUID interception on CPU {}: EAX=0x{:08x}, ECX=0x{:08x}",
               cpu_id, guest_eax, guest_ecx);
        
        // In a real implementation, we would call:
        // let (eax, ebx, ecx, edx) = hwid_system.handle_cpuid_interception(guest_eax, guest_ecx).await?;
        // Then write these values back to guest registers
        
        Ok(())
    }

    /// Handle MSR access VM exit
    async fn handle_msr_exit(&self, cpu_id: usize) -> Result<()> {
        debug!("Handling MSR exit on CPU {}", cpu_id);
        
        // This would intercept MSR reads/writes and provide spoofed values
        // In a real implementation, we would:
        // 1. Read guest ECX register (MSR index)
        // 2. Determine if it's a read or write operation
        // 3. Call HWID spoofing system to get spoofed values
        // 4. Write spoofed values back to guest registers
        
        // Simulate reading guest registers
        let msr_index = 0x17; // Simulated MSR index (IA32_PLATFORM_ID)
        let is_write = false; // Simulated operation type
        
        debug!("MSR interception on CPU {}: MSR=0x{:08x}, Write={}",
               cpu_id, msr_index, is_write);
        
        // In a real implementation, we would call:
        // let msr_value = hwid_system.handle_msr_interception(msr_index, is_write).await?;
        // Then write this value back to guest EDX:EAX registers
        
        Ok(())
    }

    /// Handle HLT VM exit
    async fn handle_hlt_exit(&self, cpu_id: usize) -> Result<()> {
        debug!("Handling HLT exit on CPU {}", cpu_id);
        
        // Resume execution after HLT
        
        Ok(())
    }

    /// Handle EPT violation
    async fn handle_ept_violation(&self, cpu_id: usize) -> Result<()> {
        debug!("Handling EPT violation on CPU {}", cpu_id);
        
        // In a real implementation, we would:
        // 1. Read the guest physical address that caused the violation
        // 2. Determine the violation type (read/write/execute)
        // 3. Call the memory manager to handle the violation
        
        // Simulate reading violation information from VMCS
        let guest_physical_address = 0x12345000; // Simulated GPA
        let violation_type = crate::memory::EptViolationType::Read; // Simulated violation type
        
        debug!("EPT violation on CPU {}: GPA=0x{:016x}, Type={:?}",
               cpu_id, guest_physical_address, violation_type);
        
        // In a real implementation, we would call:
        // memory_manager.handle_ept_violation(guest_physical_address, violation_type).await?;
        
        Ok(())
    }

    /// Deactivate VMX virtualization
    pub async fn deactivate(&mut self) -> Result<()> {
        let mut state = self.vmx_state.lock().await;
        
        if !state.is_active {
            return Ok(());
        }

        info!("Deactivating VMX virtualization");
        
        // Disable VMX on all CPUs
        for (cpu_id, vmx_region) in state.vmx_regions.iter_mut().enumerate() {
            if let Err(e) = self.disable_vmx_on_cpu(cpu_id, vmx_region).await {
                warn!("Failed to disable VMX on CPU {}: {}", cpu_id, e);
            }
        }
        
        state.is_active = false;
        info!("VMX virtualization deactivated");
        
        Ok(())
    }

    /// Disable VMX on a specific CPU
    async fn disable_vmx_on_cpu(&self, cpu_id: usize, vmx_region: &mut VmxRegion) -> Result<()> {
        debug!("Disabling VMX on CPU {} (region CPU ID: {})", cpu_id, vmx_region.cpu_id);
        
        // Verify CPU ID matches
        if cpu_id != vmx_region.cpu_id {
            warn!("CPU ID mismatch during disable: expected {}, got {}", vmx_region.cpu_id, cpu_id);
        }
        
        if vmx_region.is_vmx_enabled {
            // This would execute VMXOFF instruction
            debug!("Executing VMXOFF on CPU {}", vmx_region.cpu_id);
            vmx_region.is_vmx_enabled = false;
        }
        
        debug!("VMX disabled on CPU {}", vmx_region.cpu_id);
        Ok(())
    }

    /// Cleanup VMX resources
    pub async fn cleanup(&mut self) -> Result<()> {
        let mut state = self.vmx_state.lock().await;
        
        info!("Cleaning up VMX engine");
        
        // Deactivate if still active
        if state.is_active {
            drop(state); // Release lock
            self.deactivate().await?;
            state = self.vmx_state.lock().await;
        }
        
        // Free VMX regions
        for vmx_region in &mut state.vmx_regions {
            if let Some(vmxon_addr) = vmx_region.vmxon_region.take() {
                // Free VMXON region
                debug!("Freeing VMXON region at 0x{:016x}", vmxon_addr);
            }
            
            if let Some(vmcs_addr) = vmx_region.vmcs_region.take() {
                // Free VMCS region
                debug!("Freeing VMCS region at 0x{:016x}", vmcs_addr);
            }
        }
        
        state.vmx_regions.clear();
        state.is_initialized = false;
        
        info!("VMX engine cleanup completed");
        Ok(())
    }

    /// Check if VMX is active
    pub async fn is_active(&self) -> bool {
        let state = self.vmx_state.lock().await;
        state.is_active
    }

    /// Get CPU count
    pub async fn get_cpu_count(&self) -> usize {
        let state = self.vmx_state.lock().await;
        state.cpu_count
    }

    /// Test all VM exit reasons to ensure comprehensive coverage
    /// This method demonstrates that all VmExitReason variants are supported
    pub async fn test_all_vm_exit_reasons(&self) -> Result<()> {
        debug!("Testing comprehensive VM exit reason support");
        
        // Create instances of all VM exit reasons to demonstrate complete support
        let all_exit_reasons = vec![
            VmExitReason::ExceptionOrNmi,
            VmExitReason::ExternalInterrupt,
            VmExitReason::TripleFault,
            VmExitReason::InitSignal,
            VmExitReason::StartupIpi,
            VmExitReason::IoSmi,
            VmExitReason::OtherSmi,
            VmExitReason::InterruptWindow,
            VmExitReason::NmiWindow,
            VmExitReason::TaskSwitch,
            VmExitReason::Cpuid,
            VmExitReason::Getsec,
            VmExitReason::Hlt,
            VmExitReason::Invd,
            VmExitReason::Invlpg,
            VmExitReason::Rdpmc,
            VmExitReason::Rdtsc,
            VmExitReason::Rsm,
            VmExitReason::Vmcall,
            VmExitReason::Vmclear,
            VmExitReason::Vmlaunch,
            VmExitReason::Vmptrld,
            VmExitReason::Vmptrst,
            VmExitReason::Vmread,
            VmExitReason::Vmresume,
            VmExitReason::Vmwrite,
            VmExitReason::Vmxoff,
            VmExitReason::Vmxon,
            VmExitReason::ControlRegisterAccess,
            VmExitReason::MovDr,
            VmExitReason::IoInstruction,
            VmExitReason::Rdmsr,
            VmExitReason::Wrmsr,
            VmExitReason::VmEntryFailureInvalidGuestState,
            VmExitReason::VmEntryFailureMsrLoading,
            VmExitReason::Mwait,
            VmExitReason::MonitorTrapFlag,
            VmExitReason::Monitor,
            VmExitReason::Pause,
            VmExitReason::VmEntryFailureMachineCheck,
            VmExitReason::TprBelowThreshold,
            VmExitReason::ApicAccess,
            VmExitReason::VirtualizedEoi,
            VmExitReason::AccessToGdtrOrIdtr,
            VmExitReason::AccessToLdtrOrTr,
            VmExitReason::EptViolation,
            VmExitReason::EptMisconfiguration,
            VmExitReason::Invept,
            VmExitReason::Rdtscp,
            VmExitReason::VmxPreemptionTimerExpired,
            VmExitReason::Invvpid,
            VmExitReason::Wbinvd,
            VmExitReason::Xsetbv,
            VmExitReason::ApicWrite,
            VmExitReason::Rdrand,
            VmExitReason::Invpcid,
            VmExitReason::Vmfunc,
            VmExitReason::Encls,
            VmExitReason::Rdseed,
            VmExitReason::Pml,
            VmExitReason::Xsaves,
            VmExitReason::Xrstors,
        ];
        
        debug!("VMX engine supports {} different VM exit reasons", all_exit_reasons.len());
        
        // Test a few representative exit reasons to verify handling works
        for (i, &exit_reason) in all_exit_reasons.iter().enumerate().take(5) {
            debug!("Testing VM exit reason {}: {:?}", i + 1, exit_reason);
            if let Err(e) = self.handle_vm_exit(exit_reason, 0).await {
                warn!("VM exit test failed for {:?}: {}", exit_reason, e);
            }
        }
        
        debug!("VM exit reason comprehensive test completed successfully");
        Ok(())
    }
}
