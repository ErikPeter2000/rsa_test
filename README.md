# RSA Encryption - Educational Implementation

This project was developed for educational purposes. It should not be used in production.

An implementation of the RSA encryption algorithm in Rust, based on [this paper](https://people.csail.mit.edu/rivest/Rsapaper.pdf) by R.L. Rivest, A. Shamir, and L. Adleman.

## This Project Demonstrates

1. **RSA Key Generation**: Creating public/private keypairs
2. **Prime Number Generation**: Using the Solovay-Strassen primality test
3. **Modular Arithmetic**: Operations in number theory, mostly handled by the [BigUint](https://docs.rs/num-bigint/latest/num_bigint/struct.BigUint.html) struct
4. **Block Cipher Mode**: Handling messages longer than the key size

## Getting Started

### Prerequisites

- Rust 1.70 or later (with Cargo)

### Installation

```bash
git clone <repository-url>
cd rsa_test
cargo build --release
```

### Running the Demo

```bash
cargo run
```

This will:
1. Generate a 512-bit RSA keypair
2. Read plaintext from `text/text00.txt`
3. Encrypt the message
4. Decrypt it back to plaintext
5. Display both the ciphertext (hex) and decrypted message

### Running Tests

```bash
cargo test
```

The test suite includes:
- Encryption/decryption correctness tests
- Edge case handling
- Primality test validation
- Input validation checks

## Project Structure

```
rsa_test/
├── Cargo.toml              # Project dependencies
├── README.md               # This file
├── src/
│   ├── main.rs             # Demo application
│   └── rsa_test.rs         # RSA implementation + tests
└── text/
    ├── text00.txt          # Sample plaintext (short)
    └── text01.txt          # Sample plaintext (long)
```

## Dependencies

```toml
num-bigint = "0.4"      # Arbitrary-precision integers
num-integer = "0.1"     # Integer traits (gcd, mod operations)
num-traits = "0.2"      # Numeric traits
rand = "0.8"            # Random number generation
hex = "0.4"             # Hex encoding for display
```

## Known Limitations

1. **No Padding**: Vulnerable to mathematical attacks
2. **Deterministic**: Same plaintext results in the same ciphertext
3. **Small Message Space**: Without padding, predictable messages are weak
4. **Timing Attacks**: Not constant-time implementation
