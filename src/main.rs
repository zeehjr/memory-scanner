use crate::process32::Process32;

mod process32;
mod windows_modules;

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
