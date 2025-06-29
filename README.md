# high level cryptograhpy library (hcl)

hcl provides implementations of various cryptograhic concepts such as ratchet.

It is backed by the excellent and well-audited [libsodium](https://doc.libsodium.org/).

## Getting started
To get started, just create an instance of the Hcl struct like so:
```rust
let hcl = Hcl::new().unwrap();
```

After that, you can use the library through this variable. For more information, see
[examples](https://github.com/Apfelfrosch/hcl/main/examples) or [tests](https://github.com/Apfelfrosch/hcl/tree/main/src/tests.rs)

## Features implemented
- Key generation
  - Symmetric Keys
  - Public/Private KeyPair
  - Public/Private Signing KeyPair
- Cryptographically secure random data generation
  - Generate a random bytes and store into buffer
  - Generate a random number in a uniform distribution
- Cryptographic signatures
- Key derivation
- Message padding
- Ratchets
- Base64 encoding and decoding
