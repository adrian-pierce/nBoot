extern crate alloc;
use alloc::vec::Vec;
use core::fmt;

use uefi::fs::{FileSystem, Path};
use uefi::{boot, CString16};

const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const EI_CLASS_64: u8 = 2;
const EI_DATA_LSB: u8 = 1;
const EM_X86_64: u16 = 62;
const ET_EXEC: u16 = 2;

pub const ET_DYN: u16 = 3;
pub const PT_LOAD: u32 = 1;

const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    TooShort,
    BadMagic,
    Not64Bit,
    NotLittleEndian,
    NotX86_64(u16),
    UnsupportedType(u16),
    BadProgramHeaderSize(u16),
    ProgramHeaderTableOutOfBounds,
    SegmentOutOfBounds { vaddr: u64 },
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "File is shorter than the {} byte ELF header", EHDR_SIZE),
            Self::BadMagic => write!(f, "Not an ELF file (bad magic)"),
            Self::Not64Bit => write!(f, "Not a 64-bit ELF"),
            Self::NotLittleEndian => write!(f, "Not little-endian"),
            Self::NotX86_64(m) => write!(f, "ELF machine {} is not x86_64 ({})", m, EM_X86_64),
            Self::UnsupportedType(t) => write!(f, "e_type {} is not ET_EXEC or ET_DYN", t),
            Self::BadProgramHeaderSize(s) => write!(f, "e_phentsize {} != {}", s, PHDR_SIZE),

            Self::ProgramHeaderTableOutOfBounds => {
                write!(f, "Program header table extends past end of file")
            }

            Self::SegmentOutOfBounds { vaddr } => {
                write!(f, "PT_LOAD segment at vaddr {:#x} extends past end of file", vaddr)
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Elf64Header {
    pub e_type: u16,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_phnum: u16,
}

#[allow(unused)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

impl Elf64ProgramHeader {
    #[inline]
    pub fn is_load(&self) -> bool {
        return self.p_type == PT_LOAD;
    }

    pub fn file_data<'d>(&self, elf_data: &'d [u8]) -> Result<&'d [u8], ElfError> {
        let start = self.p_offset as usize;
        let end = start.checked_add(self.p_filesz as usize).ok_or(ElfError::SegmentOutOfBounds { vaddr: self.p_vaddr })?;

        return elf_data.get(start..end).ok_or(ElfError::SegmentOutOfBounds { vaddr: self.p_vaddr });
    }
}

#[inline]
fn read_u16(data: &[u8], off: usize) -> Result<u16, ElfError> {
    let b = data.get(off..off + 2).ok_or(ElfError::TooShort)?;

    return Ok(u16::from_le_bytes([b[0], b[1]]));
}

#[inline]
fn read_u32(data: &[u8], off: usize) -> Result<u32, ElfError> {
    let b = data.get(off..off + 4).ok_or(ElfError::TooShort)?;

    return Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
}

#[inline]
fn read_u64(data: &[u8], off: usize) -> Result<u64, ElfError> {
    let b = data.get(off..off + 8).ok_or(ElfError::TooShort)?;

    return Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]));
}

impl Elf64Header {
    pub fn parse(data: &[u8]) -> Result<Self, ElfError> {
        if data.len() < EHDR_SIZE {
            return Err(ElfError::TooShort);
        }

        if data[0..4] != ELF_MAGIC {
            return Err(ElfError::BadMagic);
        }

        if data[4] != EI_CLASS_64 {
            return Err(ElfError::Not64Bit);
        }

        if data[5] != EI_DATA_LSB {
            return Err(ElfError::NotLittleEndian);
        }

        let e_type = read_u16(data, 16)?;
        let e_machine = read_u16(data, 18)?;
        let e_entry = read_u64(data, 24)?;
        let e_phoff = read_u64(data, 32)?;
        let e_phentsize = read_u16(data, 54)?;
        let e_phnum = read_u16(data, 56)?;

        if e_machine != EM_X86_64 {
            return Err(ElfError::NotX86_64(e_machine));
        }

        if e_type != ET_EXEC && e_type != ET_DYN {
            return Err(ElfError::UnsupportedType(e_type));
        }

        if e_phentsize as usize != PHDR_SIZE {
            return Err(ElfError::BadProgramHeaderSize(e_phentsize));
        }

        let phoff = e_phoff as usize;
        let phend = phoff.checked_add((e_phnum as usize).saturating_mul(PHDR_SIZE)).ok_or(ElfError::ProgramHeaderTableOutOfBounds)?;

        if phend > data.len() {
            return Err(ElfError::ProgramHeaderTableOutOfBounds);
        }

        return Ok(Self { e_type, e_entry, e_phoff, e_phnum });
    }

    pub fn program_headers<'a>(&self, data: &'a [u8]) -> impl Iterator<Item = Elf64ProgramHeader> + 'a {
        return ProgramHeaderIter {
            data,
            base: self.e_phoff as usize,
            count: self.e_phnum,
            index: 0,
        };
    }
}

struct ProgramHeaderIter<'a> {
    data: &'a [u8],
    base: usize,
    count: u16,
    index: u16,
}

impl<'a> Iterator for ProgramHeaderIter<'a> {
    type Item = Elf64ProgramHeader;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.count {
            return None;
        }

        let off = self.base + (self.index as usize) * PHDR_SIZE;
        self.index += 1;

        return Some(Elf64ProgramHeader {
            p_type:   read_u32(self.data, off +  0).expect("ProgramHeader bounds violated"),
            p_flags:  read_u32(self.data, off +  4).expect("ProgramHeader bounds violated"),
            p_offset: read_u64(self.data, off +  8).expect("ProgramHeader bounds violated"),
            p_vaddr:  read_u64(self.data, off + 16).expect("ProgramHeader bounds violated"),
            p_paddr:  read_u64(self.data, off + 24).expect("ProgramHeader bounds violated"),
            p_filesz: read_u64(self.data, off + 32).expect("ProgramHeader bounds violated"),
            p_memsz:  read_u64(self.data, off + 40).expect("ProgramHeader bounds violated"),
            p_align:  read_u64(self.data, off + 48).expect("ProgramHeader bounds violated"),
        });
    }
}

pub fn read_kernel_file(path: &str) -> Vec<u8> {
    let fs_handle = boot::get_image_file_system(boot::image_handle()).expect("Failed to obtain image file system");
    let mut fs = FileSystem::new(fs_handle);
    let c_path = CString16::try_from(path).expect("Kernel path contains invalid UTF-16");

    return fs.read(Path::new(&c_path)).expect("Failed to read kernel file from ESP");
}

pub fn load_kernel_elf(path: &str) -> (Vec<u8>, Elf64Header) {
    let data = read_kernel_file(path);
    let header = Elf64Header::parse(&data).unwrap_or_else(|e| panic!("ELF parse failed: {e}"));

    return (data, header);
}
