use std::os::raw::c_void;

use windows::Win32::{
    Foundation::HANDLE,
    System::{
        Diagnostics::{Debug::ReadProcessMemory, ToolHelp::MODULEENTRY32W},
        Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_READWRITE,
        },
        Threading::{OpenProcess, PROCESS_ALL_ACCESS},
    },
};

use crate::windows_modules::{list_process_module_names, list_process_modules};

pub struct Process32 {
    pub handle: HANDLE,
    pub process_id: u32,
}

pub type Address32 = u32;

#[allow(dead_code)]
impl Process32 {
    pub fn new(process_id: u32) -> Result<Self, windows::core::Error> {
        let result = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, process_id) };

        match result {
            Ok(handle) => Ok(Process32 { handle, process_id }),
            Err(error) => Err(error),
        }
    }

    fn read_dword(&self, address: i32) -> i32 {
        let mut buffer: [u8; 4] = [0; 4];

        unsafe {
            ReadProcessMemory(
                self.handle,
                address as *const c_void,
                buffer.as_mut_ptr().cast(),
                4,
                None,
            )
            .unwrap_or(())
        };

        i32::from_le_bytes(buffer)
    }

    pub fn read_buffer(&self, address: u32, size: usize) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![0; size];

        unsafe {
            ReadProcessMemory(
                self.handle,
                address as *const c_void,
                buffer.as_mut_ptr().cast(),
                size,
                None,
            )
            .unwrap_or(());
        }

        return buffer;
    }

    pub fn list_module_names(&self) -> Result<Vec<String>, windows::core::Error> {
        list_process_module_names(self.handle)
    }

    pub fn list_modules(&self) -> Vec<MODULEENTRY32W> {
        list_process_modules(self.process_id)
    }

    pub fn query_memory_info(&self, address: u32) -> MEMORY_BASIC_INFORMATION {
        let mut data: MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION::default();
        let size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

        unsafe { VirtualQueryEx(self.handle, Some(address as *const c_void), &mut data, size) };

        data
    }

    pub fn scan_dword(&self, value: i32, start_address: u32, end_address: u32) -> Vec<u32> {
        let aob = value.to_le_bytes();

        self.scan_aob(&aob, start_address, end_address)
    }

    pub fn scan_aob(&self, aob: &[u8], start_address: u32, end_address: u32) -> Vec<u32> {
        let mut matching_addresses: Vec<u32> = vec![];

        let mut current_address: u32 = start_address;

        while current_address < end_address {
            let mem_info = self.query_memory_info(current_address);

            if mem_info.State == MEM_COMMIT
                && mem_info.Protect & PAGE_GUARD != PAGE_GUARD
                && mem_info.Protect & PAGE_READWRITE == PAGE_READWRITE
            {
                let buffer = self.read_buffer(mem_info.BaseAddress as u32, mem_info.RegionSize);

                let mut current = 0;
                let mut current_aob_address: u32 = mem_info.BaseAddress as u32;

                for offset in 0..buffer.len() {
                    if buffer[offset] == aob[current] {
                        if current == 0 {
                            current_aob_address = mem_info.BaseAddress as u32 + offset as u32;
                        }

                        current = current + 1;
                    } else {
                        current = 0;
                    }

                    if current == aob.len() {
                        matching_addresses.push(current_aob_address);
                        current = 0;
                    }
                }
            }

            current_address = mem_info.BaseAddress as u32 + mem_info.RegionSize as u32;
        }

        matching_addresses
    }

    fn scan() -> Vec<Address32> {
        vec![]
    }
}
