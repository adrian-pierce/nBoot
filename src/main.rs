#![no_std]
#![no_main]

mod cpu;
mod elf;
mod kernel;

use uefi::{Status, entry};
use core::panic::PanicInfo;
use crate::cpu::enable_sse;

const KERNEL_PATH: &str = "neptune-Lovelace-0.1.0.elf";

#[entry]
fn main() -> Status {
    enable_sse();
    uefi::helpers::init().unwrap();
    uefi::println!("[nBoot INFO]: Bootloader started...");

    let (kernel_data, header) = elf::load_kernel_elf(KERNEL_PATH);
    kernel::load_segments(&kernel_data, &header);
    uefi::println!("[nBoot INFO]: Kernel segments are loaded");

    kernel::jump_to_kernel(header.e_entry);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    uefi::println!("[nBoot PANIC]: {}", info);
    loop {
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}
