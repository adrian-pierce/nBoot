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

fn apply_pie_relocations(kernel_data: &[u8], header: &elf::Elf64Header, physical_base: u64, min_vaddr: u64, image_size: u64) {
    const PT_DYNAMIC: u32 = 2;

    const DT_RELA: i64 = 7;
    const DT_RELASZ: i64 = 8;
    const DT_RELAENT: i64 = 9;

    const R_X86_64_NONE: u32 = 0;
    const R_X86_64_RELATIVE: u32 = 8;

    let mut rela_addr = None;
    let mut rela_size = 0u64;
    let mut rela_ent = 24u64;

    let mut rel_size = 0u64;
    let mut relr_size = 0u64;
    let mut plt_size = 0u64;

    for phdr in header.program_headers(kernel_data) {
        if phdr.p_type != PT_DYNAMIC {
            continue;
        }

        let data = phdr.file_data(kernel_data).expect("Invalid PT_DYNAMIC segment");
        assert!(data.len() % 16 == 0, "Invalid ELF dynamic table");

        for entry in data.chunks_exact(16) {
            let tag = i64::from_le_bytes(entry[0..8].try_into().unwrap());
            let value = u64::from_le_bytes(entry[8..16].try_into().unwrap());

            match tag {
                0 => break,
                DT_RELA => rela_addr = Some(value),
                DT_RELASZ => rela_size = value,
                DT_RELAENT => rela_ent = value,

                18 => rel_size = value,  // DT_RELSZ
                35 => relr_size = value, // DT_RELRSZ
                2 => plt_size = value,   // DT_PLTRELSZ

                _ => {},
            }
        }
    }

    assert!(rel_size == 0 && relr_size == 0 && plt_size == 0, "Unsupported ELF relocation format");
    if rela_size == 0 {
        return;
    }

    assert_eq!(rela_ent, 24, "Unsupported ELF RELA entry size");
    assert!(rela_size % rela_ent == 0, "Invalid ELF RELA table size");

    let rela_addr = rela_addr.expect("Missing ELF RELA address");
    let rela_offset = rela_addr.checked_sub(min_vaddr).expect("RELA address below image");

    assert!(rela_offset <= image_size && rela_size <= image_size - rela_offset, "RELA table outside kernel image");

    let count = rela_size / rela_ent;
    let load_bias = physical_base.wrapping_sub(min_vaddr);

    for i in 0..count {
        let entry_addr = physical_base.checked_add(rela_offset).and_then(|n| n.checked_add(i * rela_ent))
            .expect("RELA entry address overflow");

        let entry = unsafe {
            core::slice::from_raw_parts(entry_addr as *const u8, 24)
        };

        let r_offset = u64::from_le_bytes(
            entry[0..8].try_into().unwrap()
        );

        let r_info = u64::from_le_bytes(
            entry[8..16].try_into().unwrap()
        );

        let r_addend = i64::from_le_bytes(
            entry[16..24].try_into().unwrap()
        );

        let relocation_type = r_info as u32;
        let symbol_index = r_info >> 32;

        if relocation_type == R_X86_64_NONE {
            continue;
        }

        assert!(relocation_type == R_X86_64_RELATIVE && symbol_index == 0, "Unsupported x86_64 relocation");
        let target_offset = r_offset.checked_sub(min_vaddr).expect("Relocation below kernel image");
        assert!(target_offset <= image_size && 8 <= image_size - target_offset, "Relocation target outside kernel image");
        let target = physical_base.checked_add(target_offset).expect("Relocation address overflow");
        let value = load_bias.wrapping_add(r_addend as u64);

        unsafe {
            ptr::write_unaligned(target as *mut u64, value);
        }
    }
}

pub fn load_segments(kernel_data: &[u8], header: &elf::Elf64Header) -> u64 {
    const PAGE_SIZE: u64 = 4096;
    const PAGE_MASK: u64 = PAGE_SIZE - 1;

    assert_eq!(header.e_type, elf::ET_DYN, "Neptune requires an ET_DYN kernel");

    let mut min_vaddr = u64::MAX;
    let mut max_vaddr = 0u64;
    let mut max_align = PAGE_SIZE;
    let mut entry_valid = false;

    for phdr in header.program_headers(kernel_data) {
        if !phdr.is_load() {
            continue;
        }

        assert!(phdr.p_filesz <= phdr.p_memsz, "Invalid ELF segment sizes");

        if phdr.p_memsz == 0 {
            continue;
        }

        let data = phdr.file_data(kernel_data).expect("Invalid ELF segment file range");
        assert_eq!(data.len() as u64, phdr.p_filesz, "Invalid ELF file size");

        let segment_end = phdr.p_vaddr.checked_add(phdr.p_memsz).expect("ELF address overflow");
        let page_start = phdr.p_vaddr & !PAGE_MASK;
        let page_end = segment_end.checked_add(PAGE_MASK).expect("ELF alignment overflow") & !PAGE_MASK;

        min_vaddr = min_vaddr.min(page_start);
        max_vaddr = max_vaddr.max(page_end);

        if phdr.p_align > 1 {
            assert!(phdr.p_align.is_power_of_two(), "Invalid ELF alignment");
            max_align = max_align.max(phdr.p_align);
        }

        // PF_X = executable
        if (phdr.p_flags & 1) != 0 && header.e_entry >= phdr.p_vaddr && header.e_entry < segment_end {
            entry_valid = true;
        }
    }

    assert!(min_vaddr != u64::MAX, "ELF has no loadable segments");
    assert!(entry_valid, "ELF entry point is not executable");

    let image_size = max_vaddr.checked_sub(min_vaddr).expect("Invalid ELF address range");
    let allocation_size = image_size.checked_add(max_align - PAGE_SIZE).expect("Kernel allocation size overflow");
    let num_pages = usize::try_from(allocation_size / PAGE_SIZE).expect("Kernel image too large");

    let allocation = boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, num_pages)
        .expect("Failed to allocate kernel memory");

    let raw_base = allocation.as_ptr() as u64;
    let adjustment = min_vaddr.wrapping_sub(raw_base) & (max_align - 1);
    let physical_base = raw_base.checked_add(adjustment).expect("Kernel base address overflow");

    assert!(physical_base.checked_add(image_size).expect("Kernel image end overflow") <= raw_base.checked_add(allocation_size)
        .expect("Kernel allocation end overflow"), "Kernel alignment exceeds allocation");

    unsafe {
        ptr::write_bytes(physical_base as *mut u8, 0, usize::try_from(image_size).expect("Kernel image too large"));
    }

    for phdr in header.program_headers(kernel_data) {
        if !phdr.is_load() || phdr.p_memsz == 0 {
            continue;
        }

        let data = phdr.file_data(kernel_data).expect("Invalid ELF segment");
        let offset = phdr.p_vaddr - min_vaddr;
        let destination = physical_base.checked_add(offset).expect("Kernel destination overflow");

        unsafe {
            ptr::copy_nonoverlapping(data.as_ptr(), destination as *mut u8, data.len());
        }
    }

    apply_pie_relocations(kernel_data, header, physical_base, min_vaddr, image_size);
    let entry_offset = header.e_entry - min_vaddr;
    physical_base.checked_add(entry_offset).expect("Kernel entry address overflow")
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
        boot::open_protocol::<GraphicsOutput>(
            OpenProtocolParams {
                handle: gop_handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }.expect("Failed to open GOP");

    let mode_info = gop.current_mode_info();
    let (width, height) = mode_info.resolution();
    let stride = mode_info.stride();

    let pixel_format = match mode_info.pixel_format() {
        PixelFormat::Rgb => 0,
        PixelFormat::Bgr => 1,

        PixelFormat::Bitmask => {
            panic!("Unsupported GOP bitmask format");
        }

        PixelFormat::BltOnly => {
            panic!("GOP mode has no directly accessible framebuffer");
        }
    };

    let mut fb = gop.frame_buffer();
    let fb_addr = fb.as_mut_ptr() as u64;

    const STACK_PAGES: usize = 16;
    const PAGE_SIZE: usize = 4096;

    let stack = boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, STACK_PAGES).expect("Failed to allocate kernel stack");
    let stack_top = stack.as_ptr() as u64 + (STACK_PAGES * PAGE_SIZE) as u64;

    let boot_info_storage = boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1).expect("Failed to allocate BootInfo");
    let rsdp_addr = get_rsdp_addr();

    // After this call, no more UEFI boot services!
    let memory_map = unsafe {
        boot::exit_boot_services(None)
    };

    let meta = memory_map.meta();
    let mmap_addr = memory_map.buffer().as_ptr() as u64;
    let mmap_size = meta.map_size as u64;
    let mmap_desc_size = meta.desc_size as u64;
    let boot_info_ptr = boot_info_storage.as_ptr().cast::<BootInfo>();

    unsafe {
        boot_info_ptr.write(BootInfo {
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
        });

        core::arch::asm!(
            "cli",                  // Disable maskable interrupts
            "mov rsp, {stack}",     // Switch to kernel stack
            "push 0",               // Dummy return address
            "jmp {entry}",          // Transfer control to Neptune

            stack = in(reg) stack_top,
            entry = in(reg) entry,

            // System V ABI: first argument goes in RDI.
            in("rdi") boot_info_ptr as *const BootInfo,

            options(noreturn),
        );
    }
}
