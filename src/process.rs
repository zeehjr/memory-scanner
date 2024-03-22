use std::{marker::PhantomData, ops::Add, os::raw::c_void};

use windows::Win32::{
    Foundation::HANDLE,
    System::{
        Diagnostics::Debug::ReadProcessMemory,
        Memory::{
            VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_READWRITE,
        },
        Threading::{OpenProcess, PROCESS_ALL_ACCESS},
    },
};

#[allow(dead_code)]
pub type Process32 = Process<u32>;

#[allow(dead_code)]
pub type Process64 = Process<u64>;

pub trait Address: Copy + Add<Self, Output = Self> {
    fn from_ptr(ptr: *const c_void) -> Self;
    fn from_usize(usize: usize) -> Self;
    fn as_ptr(&self) -> *const c_void;
    fn as_usize(&self) -> usize;
}

impl Address for u32 {
    fn from_ptr(ptr: *const c_void) -> Self {
        ptr as Self
    }

    fn from_usize(usize: usize) -> Self {
        usize as Self
    }

    fn as_ptr(&self) -> *const c_void {
        *self as *const c_void
    }

    fn as_usize(&self) -> usize {
        (*self).try_into().unwrap()
    }
}

impl Address for u64 {
    fn from_ptr(ptr: *const c_void) -> Self {
        ptr as Self
    }

    fn from_usize(usize: usize) -> Self {
        usize as Self
    }

    fn as_ptr(&self) -> *const c_void {
        *self as *const c_void
    }

    fn as_usize(&self) -> usize {
        (*self).try_into().unwrap()
    }
}

pub struct Process<T: Address> {
    pub handle: HANDLE,
    pub process_id: u32,
    _address_type: PhantomData<T>,
}

impl<T: Address> Process<T> {
    pub fn new(process_id: u32) -> Result<Self, windows::core::Error> {
        let result = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, process_id) };

        match result {
            Ok(handle) => Ok(Process {
                handle,
                process_id,
                _address_type: PhantomData,
            }),
            Err(error) => Err(error),
        }
    }

    #[allow(dead_code)]
    fn read_dword(&self, address: T) -> i32 {
        let mut buffer: [u8; 4] = [0; 4];

        unsafe {
            ReadProcessMemory(
                self.handle,
                address.as_ptr(),
                buffer.as_mut_ptr().cast(),
                4,
                None,
            )
            .unwrap_or(())
        };

        i32::from_le_bytes(buffer)
    }

    pub fn read_buffer(&self, address: *const c_void, size: usize) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![0; size];

        unsafe {
            ReadProcessMemory(self.handle, address, buffer.as_mut_ptr().cast(), size, None)
                .unwrap_or(());
        }

        return buffer;
    }

    pub fn scan_dword(&self, value: i32, start_address: T, end_address: T) -> Vec<T> {
        let aob = value.to_le_bytes();

        self.scan_aob(&aob, start_address, end_address)
    }

    pub fn scan_aob(&self, aob: &[u8], start_address: T, end_address: T) -> Vec<T> {
        let mut matching_addresses: Vec<T> = vec![];

        let mut current_address: T = start_address;

        while current_address.as_usize() < end_address.as_usize() {
            let mem_info = self.query_memory_info(current_address);

            if mem_info.State == MEM_COMMIT
                && mem_info.Protect & PAGE_GUARD != PAGE_GUARD
                && mem_info.Protect & PAGE_READWRITE == PAGE_READWRITE
            {
                let buffer = self.read_buffer(mem_info.BaseAddress, mem_info.RegionSize);

                for offset in 0..buffer.len() {
                    if buffer[offset] == aob[0] && buffer[offset..].starts_with(aob) {
                        matching_addresses
                            .push(T::from_ptr(mem_info.BaseAddress) + T::from_usize(offset))
                    }
                }
            }

            current_address = T::from_usize(mem_info.BaseAddress as usize + mem_info.RegionSize);
        }

        matching_addresses
    }

    pub fn query_memory_info(&self, address: T) -> MEMORY_BASIC_INFORMATION {
        let mut data: MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION::default();
        let size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

        unsafe { VirtualQueryEx(self.handle, Some(address.as_ptr()), &mut data, size) };

        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Define a mock implementation of the Process32 struct for testing purposes
    struct MockProcess;

    impl MockProcess {
        fn query_memory_info(&self, address: u32) -> MEMORY_BASIC_INFORMATION {
            // Mock implementation to return dummy memory information
            MEMORY_BASIC_INFORMATION::default()
        }

        fn read_buffer(&self, _address: u32, size: usize) -> Vec<u8> {
            // Mock implementation to return a buffer filled with zeros
            vec![0; size]
        }
    }

    #[test]
    fn test_scan_aob() {
        // Initialize the mock process for testing
        let process = MockProcess {};

        // Define the AOB pattern to search for
        let aob: [u8; 3] = [0x12, 0x34, 0x56];

        // Mock memory addresses for start and end
        let start_address = Address::from_ptr(std::ptr::null());
        let end_address = Address::from_ptr(std::ptr::null());

        // Call the function to test
        let result = process.scan_aob(&aob, start_address, end_address);

        // Assert the result against the expected value
        assert_eq!(result, vec![]); // Add expected result here based on your test case
    }
}
