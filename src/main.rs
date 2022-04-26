use core::mem::{MaybeUninit, transmute};
use libc::{c_int, c_void};
use std::ops::{Index, IndexMut};
use page_size;
use std::fs;

struct Executable {
    page_size: usize,
    binaries: *mut u8,
}

impl Executable {
    fn new(num_pages: usize) -> Executable {
        let page_size = page_size::get();
        println!("call new");
        let size = num_pages * page_size;
        let unit_page : MaybeUninit<*mut c_void> = MaybeUninit::uninit();
        println!("MaybeUninit");
        let mut page = unsafe{ unit_page.assume_init() };
        unsafe { 
            // allocation
            libc::posix_memalign(&mut page, page_size, size);
            println!("alloc");
            // set the permission
            libc::mprotect(page, size, libc::PROT_EXEC | libc::PROT_READ | libc::PROT_WRITE);
            println!("protect");
            // zero out
            libc::memset(page, 0x0, size);
            println!("memset");
        }
        // reinterpret for easy use.
        let binaries : *mut u8 = unsafe{ transmute(page) };
        println!("binaries");
        Executable{page_size, binaries}
    }

    fn executor(&mut self) -> extern "C" fn(c_int, *mut c_void) -> c_int {
    //fn executor(&mut self) -> extern "C" fn() -> c_int {
        unsafe { transmute(self.binaries) }
    }
}

impl Index<usize> for Executable {
    type Output = u8;

    fn index(&self, index: usize) -> &u8 {
        unsafe {&*self.binaries.offset(index as isize) }
    }
}

impl IndexMut<usize> for Executable {
    fn index_mut(&mut self, index: usize) -> &mut u8 {
        unsafe {&mut *self.binaries.offset(index as isize) }
    }
}

fn main() {
    let mut execute = Executable::new(1);
    //execute[0] = 0x48;
    //execute[1] = 0xc7;
    //execute[2] = 0xc0;
    //execute[3] = 0x03;
    //execute[4] = 0x00;
    //execute[5] = 0x00;
    //execute[6] = 0x00;
    //execute[7] = 0xc3;

    
    //55                      push   %rbp
    //48 89 e5                mov    %rsp,%rbp
    //c7 45 f8 00 00 00 00    movl   $0x0,-0x8(%rbp)
    //89 7d fc                mov    %edi,-0x4(%rbp)
    //48 89 75 f0             mov    %rsi,-0x10(%rbp)
    //8b 45 fc                mov    -0x4(%rbp),%eax
    //83 c0 03                add    $0x3,%eax
    //5d                      pop    %rbp
    //c3                      ret
    //55                      push   %rbp
    execute[0] = 0x55;
    //48 89 e5                mov    %rsp,%rbp
    execute[1] = 0x48;
    execute[2] = 0x89;
    execute[3] = 0xe5;
    //c7 45 f8 00 00 00 00    movl   $0x0,-0x8(%rbp)
    execute[4] = 0xc7;
    execute[5] = 0x45;
    execute[6] = 0xf8;
    execute[7] = 0x00;
    execute[8] = 0x00;
    execute[9] = 0x00;
    execute[10] = 0x00;
    //89 7d fc                mov    %edi,-0x4(%rbp)
    execute[11] = 0x89;
    execute[12] = 0x7d;
    execute[13] = 0xfc;
    //48 89 75 f0             mov    %rsi,-0x10(%rbp)
    execute[14] = 0x48;
    execute[15] = 0x89;
    execute[16] = 0x75;
    execute[17] = 0xf0;
    //8b 45 fc                mov    -0x4(%rbp),%eax
    execute[18] = 0x8b;
    execute[19] = 0x45;
    execute[20] = 0xfc;
    //83 c0 03                add    $0x3,%eax
    execute[21] = 0x83;
    execute[22] = 0xc0;
    execute[23] = 0x03;
    //5d                      pop    %rbp
    execute[24] = 0x5d;
    //c3                      ret
    execute[25] = 0xc3;
    println!("write the binary");
    let main = execute.executor();
    println!("return executor");
    let ret = main(10, 0 as *mut c_void);
    println!("ret: {:?}", ret);

}
