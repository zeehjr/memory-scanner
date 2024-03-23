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

/// Wrapper for process handle and ID.
#[allow(dead_code)]
pub struct ProcessInfo {
    handle: HANDLE,
    process_id: u32,
}

/// Trait representing a process.
pub trait Process {
    fn open(process_id: u32) -> anyhow::Result<Self>
    where
        Self: Sized;
    fn query_memory_info(&self, address: usize) -> anyhow::Result<MEMORY_BASIC_INFORMATION>;
    fn read_buffer(&self, address: usize, size: usize) -> anyhow::Result<Vec<u8>>;
}

impl Process for ProcessInfo {
    fn open(process_id: u32) -> anyhow::Result<Self> {
        let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, process_id)? };
        Ok(ProcessInfo { handle, process_id })
    }

    fn query_memory_info(&self, address: usize) -> anyhow::Result<MEMORY_BASIC_INFORMATION> {
        let mut mem_info = MEMORY_BASIC_INFORMATION::default();
        unsafe {
            let size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
            let ret = VirtualQueryEx(self.handle, Some(address as *const _), &mut mem_info, size);
            if ret == 0 {
                return Err(anyhow::anyhow!("VirtualQueryEx failed"));
            }
        }
        Ok(mem_info)
    }

    fn read_buffer(&self, address: usize, size: usize) -> anyhow::Result<Vec<u8>> {
        let mut buffer = vec![0u8; size];
        unsafe {
            let ret = ReadProcessMemory(
                self.handle,
                address as *const _,
                buffer.as_mut_ptr() as *mut _,
                size,
                None,
            );
            if ret.is_err() {
                return Err(anyhow::anyhow!("ReadProcessMemory failed"));
            }
        }
        Ok(buffer)
    }
}

pub trait MemoryScanner {
    fn scan_aob(&self, aob: &[u8], start_address: usize, end_address: usize) -> Vec<usize>;
}

impl<T: Process> MemoryScanner for T {
    fn scan_aob(&self, aob: &[u8], start_address: usize, end_address: usize) -> Vec<usize> {
        let mut matching_addresses = Vec::new();
        let mut current_address = start_address;

        while current_address < end_address {
            if let Ok(mem_info) = self.query_memory_info(current_address) {
                if mem_info.State == MEM_COMMIT
                    && mem_info.Protect & PAGE_GUARD != PAGE_GUARD
                    && mem_info.Protect & PAGE_READWRITE == PAGE_READWRITE
                {
                    if let Ok(buffer) =
                        self.read_buffer(mem_info.BaseAddress as usize, mem_info.RegionSize)
                    {
                        for (offset, chunk) in buffer.windows(aob.len()).enumerate() {
                            if chunk == aob {
                                matching_addresses.push(mem_info.BaseAddress as usize + offset);
                            }
                        }
                    }
                }
                current_address += mem_info.RegionSize;
            } else {
                break; // Unable to query memory info, breaking the loop.
            }
        }

        matching_addresses
    }
}

#[allow(dead_code)]
pub enum Endianess {
    LittleEndian,
    BigEndian,
}

/// Trait for scanning specific data types.
pub trait ValueTypeScanner {
    fn scan_dword(
        &self,
        value: i32,
        start_address: usize,
        end_address: usize,
        endianess: Endianess,
    ) -> Vec<usize>;
}

impl<T: MemoryScanner> ValueTypeScanner for T {
    fn scan_dword(
        &self,
        value: i32,
        start_address: usize,
        end_address: usize,
        endianess: Endianess,
    ) -> Vec<usize> {
        let bytes = match endianess {
            Endianess::LittleEndian => value.to_le_bytes(),
            Endianess::BigEndian => value.to_be_bytes(),
        };
        self.scan_aob(&bytes, start_address, end_address)
    }
}
