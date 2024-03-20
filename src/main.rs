use rayon::prelude::*;
use std::cmp;
use std::fs::File;
use std::io::Write;
use std::os::raw::c_void;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};

use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

struct Process32 {
    handle: HANDLE,
}

#[allow(dead_code)]
impl Process32 {
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

    fn read_buffer(&self, address: u32, size: usize) -> Vec<u8> {
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
}

fn open_process(pid: u32) -> Result<Process32, windows::core::Error> {
    let result = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid) };

    match result {
        Ok(handle) => Ok(Process32 { handle }),
        Err(error) => Err(error),
    }
}

fn search_for_dword(base_address: u32, buffer: Vec<u8>, value: i32) -> Vec<u32> {
    let buffer_iter = buffer.into_iter();

    // TODO: find a way to avoid cloning
    buffer_iter
        .clone()
        .enumerate()
        .filter_map(|(index, _)| {
            let dword_buffer = buffer_iter.clone().skip(index).take(4).collect::<Vec<u8>>();

            let dword_value = i32::from_le_bytes(dword_buffer.try_into().unwrap_or([0; 4]));

            if dword_value == value {
                return Some((index as u32 * 4) + base_address);
            }

            None
        })
        .collect::<Vec<u32>>()
}

fn main() -> () {
    let process = open_process(0x8a18).expect("Could not open process with the specified PID.");

    let start_address: u32 = 0x00000000;
    let end_address: u32 = 0x0fffffff;
    let chunk_size = 6_000;

    let mut results = (start_address..end_address)
        .into_par_iter()
        .step_by(chunk_size)
        .map(|addr| {
            (
                addr,
                process.read_buffer(addr, cmp::min(chunk_size, (end_address - addr) as usize)),
            )
        })
        .flat_map(|(addr, buffer)| search_for_dword(addr, buffer, 100))
        .collect::<Vec<u32>>();

    // TODO: find a way to sort inside the pipeline
    results.sort();

    println!("Total: {}", results.len());
    println!(
        "First: {:X} - Last: {:X}",
        results.first().unwrap_or(&0),
        results.last().unwrap_or(&0)
    );

    let mut file = File::create("data.txt").unwrap();

    let txt = results
        .into_iter()
        .map(|addr| format!("{:X}", addr))
        .collect::<Vec<String>>()
        .join("\n");

    file.write(txt.as_bytes()).unwrap();
}

#[cfg(test)]
mod test {}
