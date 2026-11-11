use core::ptr;
use uefi::mem::memory_map::MemoryMap;
use uefi::table::cfg::ConfigTableEntry;
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
use uefi::boot::{self, AllocateType, MemoryType, OpenProtocolAttributes, OpenProtocolParams};

use crate::elf;

#[repr(C)]
pub struct BootInfo {
    magic: u32,
    version: u32,
    fb_addr: u64,
    fb_width: u32,
    fb_height: u32,
    fb_stride: u32,
    fb_pixel_format: u32,
    mmap_addr: u64,
    mmap_size: u64,
    mmap_desc_size: u64,
    rsdp_addr: u64,
}

pub fn load_segments(kernel_data: &[u8], header: &elf::Elf64Header) {
    for phdr in header.program_headers(kernel_data) {
        if !phdr.is_load() {
            continue;
        }

        let num_pages = ((phdr.p_memsz as usize) + 0xFFF) / 0x1000;
        boot::allocate_pages(AllocateType::Address(phdr.p_vaddr), MemoryType::LOADER_DATA, num_pages).unwrap_or_else(|e| {
            panic!("Failed to allocate {} pages at {:#x}: {e}", num_pages, phdr.p_vaddr)
        });

        let data = phdr.file_data(kernel_data).expect("PT_LOAD segment extends past end of file");

        unsafe {
            ptr::copy_nonoverlapping(data.as_ptr(), phdr.p_vaddr as *mut u8, data.len());
        }

        // Zero the BSS (memory that exists but has no file data).
        let bss = phdr.bss_size();

        if bss > 0 {
            let bss_start = (phdr.p_vaddr + phdr.p_filesz) as *mut u8;
            
            unsafe {
                ptr::write_bytes(bss_start, 0, bss as usize);
            }
        }
    }
}

fn get_rsdp_addr() -> u64 {
    uefi::system::with_config_table(|table| {
        table.iter()
            // Use ConfigTableEntry::ACPI2_GUID
            .find(|entry| entry.guid == ConfigTableEntry::ACPI2_GUID)
            .map_or_else(
                || {
                    table.iter()
                        // Use ConfigTableEntry::ACPI_GUID
                        .find(|entry| entry.guid == ConfigTableEntry::ACPI_GUID)
                        .map_or(0, |entry| entry.address as usize as u64)
                },
                |entry| entry.address as usize as u64,
            )
    })
}

pub fn jump_to_kernel(entry: u64) -> ! {
    let gop_handle = boot::get_handle_for_protocol::<GraphicsOutput>().expect("GOP handle not found");
    
    let mut gop = unsafe {
        boot::open_protocol::<GraphicsOutput>(OpenProtocolParams {
                handle: gop_handle,
                agent: boot::image_handle(),
                controller: None,
            }, OpenProtocolAttributes::GetProtocol)
    }.expect("Failed to open GOP");

    let mode_info = gop.current_mode_info();
    let (width, height) = mode_info.resolution();
    let stride = mode_info.stride();
    
    let pixel_format = match mode_info.pixel_format() {
        PixelFormat::Rgb => 0,
        PixelFormat::Bgr => 1,
        PixelFormat::Bitmask => 2,
        PixelFormat::BltOnly => 3,
    };

    let mut fb = gop.frame_buffer();
    let fb_addr = fb.as_mut_ptr() as u64;

    let stack_pages = 16;
    let stack_ptr = boot::allocate_pages(
                        AllocateType::AnyPages,
                        MemoryType::LOADER_DATA,
                        stack_pages,
                    ).expect("Failed to allocate kernel stack");

    // Stacks grow downwards on x86_64, so calculate the top address
    let stack_top = stack_ptr.as_ptr() as u64 + (stack_pages * 4096) as u64;
    let rsdp_addr = get_rsdp_addr();
    let memory_map = unsafe { boot::exit_boot_services(None) };
    let mmap_slice = memory_map.buffer(); 
    let mmap_addr = mmap_slice.as_ptr() as u64;
    let mmap_size = mmap_slice.len() as u64;
    let mmap_desc_size = memory_map.meta().desc_size as u64;

    let boot_info = BootInfo {
        magic: 0x4E455054,
        version: 1,
        fb_addr,
        fb_width: width as u32,
        fb_height: height as u32,
        fb_stride: stride as u32,
        fb_pixel_format: pixel_format,
        mmap_addr,
        mmap_size,
        mmap_desc_size,
        rsdp_addr,
    };

    let boot_info_ptr = &boot_info as *const BootInfo;

    unsafe {
        core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
    }

    unsafe {
        core::arch::asm!(
            "mov rsp, {stack}",         // Switch to the top of our new 64 KiB stack
            "sub rsp, 8",               // Align to 16 bytes (mimics a `call` pushing a return address)
            "jmp {entry}",              // Jump to the kernel entry point
            stack = in(reg) stack_top,
            entry = in(reg) entry,
            in("rdi") boot_info_ptr,    // Pass BootInfo pointer in RDI
            options(noreturn)           // Tell compiler this function never returns
        );
    }
}
