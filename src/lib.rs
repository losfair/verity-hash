//! `dm-verity` hash image verifier.

use std::{
    io::{self, Read, Seek},
    mem::MaybeUninit,
};

use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct VerificationError {
    pub offset: usize,
    pub expected_hash: [u8; 32],
    pub actual_hash: [u8; 32],
}

#[repr(packed)]
struct VeritySb {
    signature: [u8; 8],
    version: u32,
    hash_type: u32,
    _uuid: [u8; 16],
    algorithm: [u8; 32],
    data_block_size: u32,
    hash_block_size: u32,
    data_blocks: u64,
    salt_size: u16,
    _pad1: [u8; 6],
    salt: [u8; 256],
    _pad2: [u8; 168],
}

/// Verifies that the dm-verity hash image provided in `hash_file` contains a
/// self-consistent Merkle tree, and the tree is also consistent with the disk
/// image provided as `data_file`. Returns the root hash if successful.
pub fn verify_and_calculate_sha256_root_hash(
    data_file: &mut impl Read,
    hash_file: &mut (impl Read + Seek),
) -> io::Result<Result<[u8; 32], VerificationError>> {
    let sb = read_superblock(hash_file)?;
    if &sb.signature != b"verity\0\0" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid superblock signature",
        ));
    }
    if sb.version != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid superblock version",
        ));
    }
    if sb.hash_type != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid hash type",
        ));
    }
    if &sb.algorithm != b"sha256\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid hash algorithm",
        ));
    }
    let salt_size = sb.salt_size as usize;
    if salt_size > sb.salt.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid salt size",
        ));
    }
    let salt = &sb.salt[..salt_size];

    if !sb.data_block_size.is_power_of_two()
        || sb.data_block_size < 512
        || sb.data_block_size > 65536
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid data block size",
        ));
    }

    if !sb.hash_block_size.is_power_of_two()
        || sb.hash_block_size < 512
        || sb.hash_block_size > 65536
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid hash block size",
        ));
    }

    let hash_file_size = hash_file.seek(io::SeekFrom::End(0))?;
    if hash_file_size <= sb.hash_block_size as u64
        || hash_file_size % sb.hash_block_size as u64 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid hash file size",
        ));
    }

    let mut current = vec![0u8; sb.hash_block_size as usize];
    let mut total_data_file_size_read = 0usize;
    let mut current_layer_end_cursor = sb.hash_block_size as u64 * 2;
    let mut next_layer_end_cursor = current_layer_end_cursor;
    let mut root_hash: Option<[u8; 32]> = None;

    for verify_cursor in
        (sb.hash_block_size as u64..hash_file_size).step_by(sb.hash_block_size as usize)
    {
        if verify_cursor == current_layer_end_cursor {
            current_layer_end_cursor = next_layer_end_cursor;
        }

        hash_file.seek(io::SeekFrom::Start(verify_cursor))?;
        hash_file.read_exact(&mut current)?;

        if root_hash.is_none() {
            let mut h = Sha256::new();
            h.update(salt);
            h.update(&current);
            root_hash = Some(h.finalize().into());
        }

        let child_from_data_file = current_layer_end_cursor >= hash_file_size;

        let (child_layer, child_block_size) = if child_from_data_file {
            if current_layer_end_cursor != hash_file_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Misaligned hash file",
                ));
            }
            (data_file as &mut dyn Read, sb.data_block_size as usize)
        } else {
            hash_file.seek(io::SeekFrom::Start(next_layer_end_cursor))?;
            (hash_file as &mut dyn Read, sb.hash_block_size as usize)
        };
        let res = verify_layer(&current, child_layer, salt, child_block_size)?;
        match res {
            Ok(x) => {
                if child_from_data_file {
                    total_data_file_size_read += x;
                }

                next_layer_end_cursor += x as u64;
            }
            Err(mut e) => {
                e.offset += next_layer_end_cursor as usize;
                return Ok(Err(e));
            }
        }
    }

    if data_file.read(&mut [0u8])? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Trailing data in data file",
        ));
    }

    if Some(total_data_file_size_read)
        != (sb.data_blocks as usize).checked_mul(sb.data_block_size as usize)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid data_blocks",
        ));
    }

    Ok(Ok(root_hash.unwrap().into()))
}

fn verify_layer(
    parent_block: &[u8],
    child_layer: &mut dyn Read,
    salt: &[u8],
    child_block_size: usize,
) -> io::Result<Result<usize, VerificationError>> {
    assert!(parent_block.len() % 32 == 0);
    let num_hashes = parent_block.len() / 32;
    let gen_hashes = |start| {
        (start..num_hashes)
            .map(|x| x * 32)
            .map(|x| &parent_block[x..x + 32])
    };

    let mut buf = vec![0u8; child_block_size];
    let mut consumed_size = 0usize;
    for (i, expected_hash) in gen_hashes(0).enumerate() {
        // end of layer?
        if expected_hash.iter().all(|x| *x == 0) {
            for that_hash in gen_hashes(i + 1) {
                if that_hash.iter().all(|x| *x == 0) {
                    continue;
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid hash tree",
                ));
            }
            break;
        }

        child_layer.read_exact(&mut buf)?;
        consumed_size += child_block_size;

        let mut h = Sha256::new();
        h.update(salt);
        h.update(&buf);
        let h = h.finalize();

        if &h[..] != expected_hash {
            eprintln!(
                "hash verification failed: expected {}, got {}",
                faster_hex::hex_string(expected_hash),
                faster_hex::hex_string(&h[..])
            );
            return Ok(Err(VerificationError {
                offset: consumed_size,
                expected_hash: expected_hash.try_into().unwrap(),
                actual_hash: h.into(),
            }));
        }
    }
    Ok(Ok(consumed_size))
}

fn read_superblock(stream: &mut impl Read) -> io::Result<VeritySb> {
    assert_eq!(std::mem::size_of::<VeritySb>(), 512);
    let mut sb: MaybeUninit<VeritySb> = MaybeUninit::uninit();
    unsafe {
        stream.read_exact(std::slice::from_raw_parts_mut(
            sb.as_mut_ptr() as *mut u8,
            std::mem::size_of::<VeritySb>(),
        ))?;
        Ok(sb.assume_init())
    }
}
