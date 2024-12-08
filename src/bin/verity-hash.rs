use std::fs::File;

use verity_hash::verify_and_calculate_sha256_root_hash;

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let mut data_file = File::open(&args[1]).unwrap();
    let mut hash_file = File::open(&args[2]).unwrap();
    let root_hash = verify_and_calculate_sha256_root_hash(&mut data_file, &mut hash_file).unwrap();
    match root_hash {
        Ok(x) => println!("{}", faster_hex::hex_string(&x)),
        Err(error_offset) => {
            eprintln!("Error at offset {}", error_offset);
            std::process::exit(1);
        }
    }
}
