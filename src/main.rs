use core::mem::{transmute, MaybeUninit, size_of};
use libc::{c_int, c_void, c_char};
use page_size;
use std::{
    convert::TryInto,
    fs,
    slice::from_raw_parts_mut,
    ffi::CString,
    cmp::{min, max}
};
use elfloader::{ElfBinary, ElfLoader, ElfLoaderErr, Flags, VAddr, RelocationEntry, LoadableHeaders, Entry};
use xmas_elf::{sections::SectionData, symbol_table::Type};
use byteorder::{ByteOrder, LittleEndian};

struct Executable { 
    // Remember the min virtual address for calculation
    min_virtual_address: usize,
    // The base address of all allocated pages.
    base_address: Option<*mut u8>,
    // the parameters for calling the `main` function in the .text
    parameters: Vec<CString>,
}

impl<'a> Executable {
    /// Create an empty Executable
    #[inline]
    fn new() -> Self {
        Self { 
            min_virtual_address: 0,
            base_address: None,
            parameters: Vec::new(),
        }
    }

    /// Allocate continous memory with minimum size `memory_size`. It is rounded up to page size.
    fn allocate_pages(memory_size: usize, address_hint: usize) -> *mut u8 {
        println!("Allocate pages with minimum size {}", memory_size);
        // round up the memory size
        let memory_size = Self::round_up_to_page_size(memory_size);
        let mut uninit_page: MaybeUninit<*mut c_void> = MaybeUninit::uninit();
        unsafe {
            // allocation via mmap.
            *uninit_page.as_mut_ptr() = libc::mmap(address_hint as *mut c_void, memory_size, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0);
            println!("mmap at address {:?} with size {}", *uninit_page.as_ptr(), memory_size);
            // zero out
            libc::memset(*uninit_page.as_mut_ptr(), 0x0, memory_size);
            println!("zero the new page(s)");
        }

        // reinterpret for easy use.
        unsafe { transmute(uninit_page.assume_init()) }
    }

    /// Return the page size of the machine.
    #[inline]
    fn page_size() -> usize {
        page_size::get()
    }

    /// Compute the round-up page numbers for `memory_size`.
    #[inline]
    fn compute_page_numbers(memory_size: usize) -> usize {
        memory_size / Self::page_size()
            + if memory_size % Self::page_size() > 0 {
                1
            } else {
                0
            }
    }

    /// Round up the `memory_size` to page size.
    #[inline]
    fn round_up_to_page_size(memory_size: usize) -> usize {
        Self::compute_page_numbers(memory_size) * Self::page_size()
    }

    /// Return the function pointer of `${entry_point}(int arvc, char ** argv)`
    #[inline]
    fn entry_point_handler(&self, elf_binary: &ElfBinary, entry_point: &str) -> Result<extern "C" fn(c_int, *mut *mut c_char) -> c_int, ElfLoaderErr> {
        let entry_point_virtual_address = find_entry_point(elf_binary, entry_point);

        println!("the {} virtual address is {:#x}", entry_point, entry_point_virtual_address);

        // manually case the type to a function pointer
        Ok(unsafe { transmute(self.virtual_to_physical_address(entry_point_virtual_address)?) })
    }

    /// Pass parameters `self.parameters` and execute `${entry_point}(int arvc, char ** argv)`.
    fn execute(&self, elf_binary: &ElfBinary, entry_point: &str) -> Result<c_int, ElfLoaderErr> {
        // prepare the parameters: copy the parameters and make char *argv[] which might be
        // modified by the binaries.
        let parameters = self.parameters.clone();
        let mut argv = Vec::new();
        for parameter in parameters {
            argv.push(parameter.into_raw());
        }
        let argc = argv.len();
        println!("call {} argc: {}, argv: {:?}", entry_point, argc, argv.as_mut_ptr());
        Ok(self.entry_point_handler(elf_binary, entry_point)?(argc.try_into().unwrap(), argv.as_mut_ptr()))
    }

    /// Add a new parameter to this executable.
    #[inline]
    fn add_parameter<T: Into<Vec<u8>>>(&mut self, parameter: T) {
        self.parameters.push(CString::new(parameter).expect("fail to parse a parameter"));
    }

    /// Reset the parameters.
    #[inline]
    fn clean_parameter(&mut self) {
        self.parameters.clear();
    }

    /// Return a Rust-style slice at the `offset` with `length`.
    #[inline]
    unsafe fn get_slice(&mut self, virtual_address: usize, length: usize) -> Result<&mut [u8], ElfLoaderErr> {
        let target_address = self.virtual_to_physical_address(virtual_address)?;
        Ok(from_raw_parts_mut(target_address, length))
    }

    /// Return the actual physical address.
    #[inline]
    unsafe fn virtual_to_physical_address(&self, virtual_address: usize) -> Result<*mut u8, ElfLoaderErr> {
        Ok(self.base_address.ok_or(ElfLoaderErr::ElfParser { source: "no allocation" })?.add(virtual_address).sub(self.min_virtual_address))
    }
}

impl ElfLoader for Executable {
    /// Calculate the pages need to load all the loadable and allocate continuous pages.
    fn allocate(&mut self, load_headers: LoadableHeaders) -> Result<(), ElfLoaderErr> {
        // Calculate the min and max virtual addresses.
        let (min, max) = load_headers.fold(None, |min_max, header|{
            let lower_addr = header.virtual_addr();
            let upper_addr = lower_addr + header.mem_size();
            min_max.map(|(cur_min, cur_max)| (min(cur_min, lower_addr), max(cur_max, upper_addr))).or_else(||Some((lower_addr, upper_addr)))
        }).ok_or(ElfLoaderErr::ElfParser { source: "no loadable section." })?;

        // allocate the pages.
        println!( "allocate virtual address from {:#x} to {:#x}", min, max);
        self.base_address = Some(Self::allocate_pages((max - min) as usize, min as usize));
        self.min_virtual_address = min as usize;
        Ok(())
    }

    /// Calculate tne relocation.
    fn relocate(&mut self, entry: RelocationEntry) -> Result<(), ElfLoaderErr> {
        use elfloader::RelocationType::x86_64;
        use elfloader::arch::x86_64::RelocationTypes::*;

        let offset = entry.offset as usize;
        let base_address = self.base_address.ok_or(ElfLoaderErr::ElfParser { source: "no allocation." })?;
        println!("Relocate type {:?},  offset: {:#x}", entry.rtype, offset);

        match entry.rtype {
            x86_64(R_AMD64_RELATIVE) => {

                let mut target_memory = unsafe { self.get_slice(offset, size_of::<u64>())? };
                // This type requires addend to be present
                let addend = entry
                    .addend
                    .ok_or(ElfLoaderErr::UnsupportedRelocationEntry)?;
                let target_value = unsafe { base_address.add(addend as usize) };

                LittleEndian::write_u64(&mut target_memory, target_value as u64);

                println!(
                    "R_RELATIVE offset {}, append {:#x}. Write u64 {:?} and the result {:02X?}",
                    offset,
                    addend,
                    target_value,
                    target_memory,
                );

                Ok(())
            },
            _type => {
                //println!("unimplemented {:?}", a);
                Ok(())
            },
        }
    }

    /// Load the binaries `region` into the expect address and change the permission to `flag`.
    fn load(&mut self, flags: Flags, base: VAddr, region: &[u8]) -> Result<(), ElfLoaderErr> {
        let base = base as usize;
        let target_memory = unsafe { self.get_slice(base, region.len())? };
        target_memory.copy_from_slice(region);
        println!("load region to offset {:#x} of size {:#x}", base, region.len());

        let permission_flag = 0 | if flags.is_execute() {
            libc::PROT_EXEC
        } else { 0 } | if flags.is_write() {
            libc::PROT_WRITE
        } else { 0 } | if flags.is_read() {
            libc::PROT_READ
        } else { 0 };
        unsafe {
            // set the permission
            libc::mprotect(
                self.virtual_to_physical_address(base)? as *mut c_void,
                Self::round_up_to_page_size(region.len()),
                permission_flag,
            );
        }
        println!("change pages at virtual offset {:#x} of size {:#x} permission to {}", base, Self::round_up_to_page_size(region.len()), permission_flag);
        Ok(())
    }

    fn tls(
        &mut self,
        tdata_start: VAddr,
        _tdata_length: u64,
        total_size: u64,
        _align: u64
    ) -> Result<(), ElfLoaderErr> {
        let tls_end = tdata_start +  total_size;
        println!("Initial TLS region is at = {:#x} -- {:#x}", tdata_start, tls_end);
        Ok(())
    }
}

// Then, with ElfBinary, a ELF file is loaded using `load`:
fn main() {
    let raw_binary = fs::read("test/test.o").expect("Can't read binary");
    let binary = ElfBinary::new(raw_binary.as_slice()).expect("Got proper ELF file");
    let mut executable = Executable::new();
    binary.load(&mut executable).expect("Can't load the binary?");
    executable.add_parameter("1");
    executable.add_parameter("22");
    executable.add_parameter("333");
    let ret = executable.execute(&binary, "main");
    println!("ret: {:?}", ret);
}

/// Return the virtual address of the function symbol of name `entry_point`.
fn find_entry_point(elf_binary: &ElfBinary, entry_point: &str) -> usize {
    // Find the `.symtab` section in the ELF file.
    let symtab = match elf_binary.file.find_section_by_name(".symtab").expect("no .symtab section")
        .get_data(&elf_binary.file).expect("cannot parse symtab") {
        SectionData::SymbolTable64(t) => t,
        _ => panic!("cannot find a symbol table 64."),
    };

    //find the offset of the `entry_point`
    let entry_point = symtab.iter().find(|symbol|{
        if let Ok(name) = symbol.get_name(&elf_binary.file) {
            if let Ok(t) = symbol.get_type() {
                if name == entry_point && t == Type::Func {
                    return true;
                }
            }
        }
        false
    }).expect(&format!("cannot find the {} symbol", entry_point));
    entry_point.value() as usize
}
