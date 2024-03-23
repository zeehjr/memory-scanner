use crate::process::{Endianess, Process, ProcessInfo, ValueTypeScanner};

mod process;
mod windows_modules;

fn main() -> () {
    let process: ProcessInfo = Process::open(0x9870).unwrap();

    let addresses = process.scan_dword(565, 0x0, 0x7fffffff, Endianess::LittleEndian);

    println!("Found addresses: {}", addresses.len());

    println!("Has address: {}", addresses.contains(&0x08027174))
}

#[cfg(test)]
mod test {}
