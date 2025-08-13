#![no_std]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

extern crate alloc;
use alloc::vec::Vec;
use wdk_sys::*;
use wdk_sys::ntddk::*;
use core::ptr;

// Global allocator for no_std environment
use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

// Simplified driver state
static mut DRIVER_INITIALIZED: bool = false;

// Driver entry point
#[no_mangle]
pub extern "C" fn DriverEntry(
    driver_object: PDRIVER_OBJECT,
    _registry_path: PUNICODE_STRING,
) -> NTSTATUS {
    unsafe {
        // Set up driver object with correct calling convention
        (*driver_object).DriverUnload = Some(driver_unload);
        (*driver_object).MajorFunction[IRP_MJ_CREATE as usize] = Some(dispatch_create);
        (*driver_object).MajorFunction[IRP_MJ_CLOSE as usize] = Some(dispatch_close);
        (*driver_object).MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(dispatch_device_control);
        
        // Create device object
        let mut device_object: PDEVICE_OBJECT = ptr::null_mut();
        let device_name = create_device_name();
        
        let status = wdk_sys::ntddk::IoCreateDevice(
            driver_object,
            0,
            &device_name,
            FILE_DEVICE_UNKNOWN,
            FILE_DEVICE_SECURE_OPEN,
            0, // FALSE
            &mut device_object,
        );
        
        if status == STATUS_SUCCESS {
            DRIVER_INITIALIZED = true;
        }
        
        status
    }
}

unsafe extern "C" fn driver_unload(_driver_object: PDRIVER_OBJECT) {
    DRIVER_INITIALIZED = false;
}

unsafe extern "C" fn dispatch_create(
    _device_object: PDEVICE_OBJECT,
    irp: PIRP,
) -> NTSTATUS {
    complete_irp(irp, STATUS_SUCCESS, 0);
    STATUS_SUCCESS
}

unsafe extern "C" fn dispatch_close(
    _device_object: PDEVICE_OBJECT,
    irp: PIRP,
) -> NTSTATUS {
    complete_irp(irp, STATUS_SUCCESS, 0);
    STATUS_SUCCESS
}

unsafe extern "C" fn dispatch_device_control(
    _device_object: PDEVICE_OBJECT,
    irp: PIRP,
) -> NTSTATUS {
    let stack_location = wdk_sys::ntddk::IoGetCurrentIrpStackLocation(irp);
    let control_code = (*stack_location).Parameters.DeviceIoControl.IoControlCode;
    
    let status = match control_code {
        0x22E004 => handle_read_memory(irp),     // READ_MEMORY
        0x22E008 => handle_get_process_info(irp), // GET_PROCESS_INFO
        0x22E00C => handle_verify_connection(irp), // VERIFY_CONNECTION
        _ => STATUS_INVALID_DEVICE_REQUEST,
    };
    
    if status != STATUS_PENDING {
        complete_irp(irp, status, 0);
    }
    
    status
}

unsafe fn handle_read_memory(_irp: PIRP) -> NTSTATUS {
    // Simplified memory read - return success for now
    STATUS_SUCCESS
}

unsafe fn handle_get_process_info(irp: PIRP) -> NTSTATUS {
    let output_buffer = (*irp).AssociatedIrp.SystemBuffer as *mut ProcessInfo;
    if !output_buffer.is_null() {
        // Return mock process info
        (*output_buffer).process_id = 12345;
        (*output_buffer).base_address = 0x140000000;
        (*output_buffer).image_size = 0x2000000;
        (*output_buffer).name = [b'R', b'6', b'S', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        
        complete_irp(irp, STATUS_SUCCESS, core::mem::size_of::<ProcessInfo>() as u64);
        return STATUS_SUCCESS;
    }
    STATUS_INVALID_PARAMETER
}

unsafe fn handle_verify_connection(irp: PIRP) -> NTSTATUS {
    let output_buffer = (*irp).AssociatedIrp.SystemBuffer as *mut ConnectionInfo;
    if !output_buffer.is_null() {
        (*output_buffer).driver_version = 1;
        (*output_buffer).build_signature = 0xDEADBEEF;
        (*output_buffer).status = 1; // Active
        (*output_buffer).capabilities = 0x07; // All capabilities
        
        complete_irp(irp, STATUS_SUCCESS, core::mem::size_of::<ConnectionInfo>() as u64);
        return STATUS_SUCCESS;
    }
    STATUS_INVALID_PARAMETER
}

unsafe fn complete_irp(irp: PIRP, status: NTSTATUS, information: u64) {
    (*irp).IoStatus.__bindgen_anon_1.Status = status;
    (*irp).IoStatus.Information = information;
    wdk_sys::ntddk::IoCompleteRequest(irp, IO_NO_INCREMENT as i8);
}

fn create_device_name() -> UNICODE_STRING {
    let device_name_str = "\\Device\\SolaraDriver\0";
    let device_name_wide: Vec<u16> = device_name_str.encode_utf16().collect();
    
    UNICODE_STRING {
        Length: ((device_name_wide.len() - 1) * 2) as u16,
        MaximumLength: (device_name_wide.len() * 2) as u16,
        Buffer: device_name_wide.as_ptr() as *mut u16,
    }
}

// Request/Response structures
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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack));
        }
    }
}
