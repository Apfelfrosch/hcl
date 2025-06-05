# high level cryptograhpy library (hcl)

hcl provides implementations of various cryptograhic concepts such as ratchet.

It is backed by the excellent and well-audited [libsodium](https://doc.libsodium.org/).

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
