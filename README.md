# verity-hash

`dm-verity` hash image verifier.

## Usage

CLI:

```bash
$ dd if=/dev/urandom of=data.img bs=1M count=10
$ veritysetup format --root-hash-file root_hash.txt data.img hash.img
$ cargo run --release data.img hash.img
```

Library:

```rust
let root_hash = verify_and_calculate_sha256_root_hash(&mut data_file, &mut hash_file)?;
```
