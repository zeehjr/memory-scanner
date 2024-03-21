use memory::Process32;
use rayon::prelude::*;
use std::cmp;
use std::fs::File;
use std::io::Write;

mod memory;
mod windows_modules;

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

#[allow(dead_code)]
fn scan() {
    let process = Process32::new(0x8a18).expect("error while trying to get access to process");

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

fn main() -> () {
    let process = Process32::new(0x00008A18).expect("error while trying to get access to process");

    // let addresses = process.scan_aob(
    //     &[0xFF, 0xFF, 0xFF, 0xFF, 0x5F, 0xFF, 0xEF, 0xFF],
    //     0x00000000,
    //     0x0fffffff,
    // );

    let addresses = process.scan_dword(565, 0x0, 0x7fffffff);

    println!("Found addresses: {}", addresses.len());

    // addresses
    //     .into_iter()
    //     .for_each(|address| println!("{:X}", address));

    println!("Has address: {}", addresses.contains(&0x0801C08C))
}

#[cfg(test)]
mod test {}
