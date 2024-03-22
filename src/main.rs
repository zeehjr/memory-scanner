use crate::process::Process64;

mod process;
mod windows_modules;

fn main() -> () {
    let process = Process64::new(0x9870).expect("error while trying to get access to process");

    let addresses = process.scan_dword(100, 0x0, 0x7fffffff);

    println!("Found addresses: {}", addresses.len());

    // addresses
    //     .into_iter()
    //     .for_each(|address| println!("{:X}", address));

    println!("Has address: {}", addresses.contains(&0x01107AF4))
}

#[cfg(test)]
mod test {}
