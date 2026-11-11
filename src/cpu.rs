use core::arch::asm;

const CR0_MP:    u64 = 1 << 1;
const CR0_EM:    u64 = 1 << 2;
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;

pub fn enable_sse() {
    // ========== CR0: clear EM, set MP ==========
    let mut cr0 = read_cr0();
    cr0 &= !CR0_EM;
    cr0 |= CR0_MP;
    write_cr0(cr0);

    // ========== CR4: set OSFXSR and OSXMMEXCPT ==========
    let mut cr4 = read_cr4();
    cr4 |= CR4_OSFXSR | CR4_OSXMMEXCPT;
    write_cr4(cr4);
}

#[inline]
fn read_cr0() -> u64 {
    let value: u64;
    unsafe {
        asm!("mov {}, cr0", out(reg) value, options(nomem, nostack, preserves_flags));
    }

    return value;
}

#[inline]
fn write_cr0(value: u64) {
    unsafe {
        asm!("mov cr0, {}", in(reg) value, options(nomem, nostack, preserves_flags));
    }
}

#[inline]
fn read_cr4() -> u64 {
    let value: u64;
    unsafe {
        asm!("mov {}, cr4", out(reg) value, options(nomem, nostack, preserves_flags));
    }

    return value;
}

#[inline]
fn write_cr4(value: u64) {
    unsafe {
        asm!("mov cr4, {}", in(reg) value, options(nomem, nostack, preserves_flags));
    }
}
