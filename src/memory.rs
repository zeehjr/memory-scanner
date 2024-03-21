use std::os::raw::c_void;

use windows::Win32::{
    Foundation::HANDLE,
    System::{
        Diagnostics::{Debug::ReadProcessMemory, ToolHelp::MODULEENTRY32W},
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

    pub fn scan_dword(&self, value: i32, start_address: u32, end_address: u32) -> Vec<u32> {
        let aob = value.to_be_bytes();

        self.scan_aob(&aob, start_address, end_address, Some(6000))
    }

    pub fn scan_aob(
        &self,
        aob: &[u8],
        start_address: u32,
        end_address: u32,
        chunk_size: Option<usize>,
    ) -> Vec<u32> {
        let chunk_size = match chunk_size {
            Some(size) => size,
            None => 6000,
        };

        let mut current_address = start_address;

        let mut buffer: Vec<u8> = vec![];

        let mut matching_addresses: Vec<u32> = vec![];

        while current_address < end_address {
            let buffer_size = std::cmp::min(chunk_size, (end_address - current_address) as usize);

            let new_buffer = self.read_buffer(current_address, buffer_size);

            let mut current_aob_address: u32 = current_address;

            if buffer.len() > aob.len() {
                let old_buffer = buffer.clone().as_slice()[buffer.len() - aob.len() + 1..].to_vec();
                buffer = [old_buffer.as_slice(), new_buffer.as_slice()].concat();

                current_aob_address = current_aob_address - aob.len() as u32 + 1;
            } else {
                buffer = new_buffer;
            }

            let mut current = 0;

            for (index, byte) in buffer.clone().into_iter().enumerate() {
                if byte == aob[current] {
                    if current == 0 {
                        current_aob_address = current_address + index as u32
                    }
                    current = current + 1
                } else {
                    current = 0
                }

                if current == aob.len() {
                    matching_addresses.push(current_aob_address);
                    current = 0;
                }
            }

            current_address = current_address + buffer_size as u32;
        }

        matching_addresses
    }

    fn scan() -> Vec<Address32> {
        vec![]
    }
}
