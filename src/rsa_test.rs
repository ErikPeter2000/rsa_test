use num_bigint::{BigUint, RandBigInt, ToBigUint};
use num_integer::Integer;
use num_traits::{One, Zero};

/// Number of iterations for the Solovay-Strassen primality test.
/// Higher values increase confidence in primality at the cost of performance.
const SOLOVAY_STRASSEN_ITERATIONS: usize = 20;

/// The public exponent commonly used in RSA (2^16 + 1).
const RSA_PUBLIC_EXPONENT: u32 = 65537;

/// Minimum recommended key size in bits for RSA.
const MIN_KEY_BITS: u64 = 512;

/// Represents an RSA key (either public or private).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub n: BigUint,
    pub exp: BigUint,
}

/// Represents an RSA keypair containing both public and private keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPair {
    pub public_key: Key,
    pub private_key: Key,
}

/// Determines the transformation mode for block processing.
#[derive(Copy, Clone)]
enum TransformMode {
    Encrypt,
    Decrypt,
}

/// Generates an RSA keypair with the specified bit length.
///
/// # Arguments
///
/// * `bits` - The bit length of the modulus n. Common values are 2048 or 4096 bits.
///   Minimum recommended value is 512 bits (for testing only).
///
/// # Returns
///
/// An RSA `KeyPair` containing the public and private keys.
///
/// # Panics
///
/// Panics if the modular inverse does not exist, which is extremely unlikely with valid primes.
///
/// # Examples
///
/// ```ignore
/// let keypair = generate_keypair(2048);
/// ```
pub fn generate_keypair(bits: u64) -> KeyPair {
    assert!(bits >= MIN_KEY_BITS, "Key size must be at least {MIN_KEY_BITS} bits");
    assert!(bits % 2 == 0, "Key size must be even");
    
    let p = generate_prime(bits / 2, SOLOVAY_STRASSEN_ITERATIONS);
    let q = generate_prime(bits / 2, SOLOVAY_STRASSEN_ITERATIONS);
    let n = &p * &q;

    let one = BigUint::one();
    let phi = (&p - &one) * (&q - &one);

    let e = RSA_PUBLIC_EXPONENT.to_biguint().unwrap();
    let d = e.modinv(&phi).expect("Modular inverse does not exist");

    KeyPair {
        public_key: Key {
            n: n.clone(),
            exp: e,
        },
        private_key: Key { n, exp: d },
    }
}

/// Encrypts the plaintext using the provided RSA public key.
/// 
/// Does not implement padding (OAEP/PKCS#1) and is insecure for real-world use.
///
/// # Arguments
///
/// * `plaintext` - The plaintext message as a byte slice.
/// * `public_key` - The RSA public key to use for encryption.
///
/// # Returns
///
/// A vector of bytes representing the encrypted ciphertext. The ciphertext
/// will be longer than the plaintext due to block padding.
pub fn encrypt(plaintext: &[u8], public_key: &Key) -> Vec<u8> {
    transform_blocks(plaintext, public_key, TransformMode::Encrypt)
}

/// Decrypts the ciphertext using the provided RSA private key.
///
/// # Arguments
///
/// * `ciphertext` - The ciphertext as a byte slice.
/// * `private_key` - The RSA private key to use for decryption.
///
/// # Returns
///
/// A vector of bytes representing the decrypted plaintext with padding removed.
pub fn decrypt(ciphertext: &[u8], private_key: &Key) -> Vec<u8> {
    transform_blocks(ciphertext, private_key, TransformMode::Decrypt)
}

/// Core transformation function that handles both encryption and decryption.
fn transform_blocks(input: &[u8], key: &Key, mode: TransformMode) -> Vec<u8> {
    let block_size = key.n.bits().div_ceil(8) as usize;
    let chunk_size = match mode {
        TransformMode::Encrypt => block_size - 1, // Ensure plaintext < n
        TransformMode::Decrypt => block_size,     // Ciphertext is always block_size
    };
    
    let mut result = Vec::new();

    for chunk in input.chunks(chunk_size) {
        let input_num = BigUint::from_bytes_be(chunk);
        let output_num = input_num.modpow(&key.exp, &key.n);
        let output_bytes = output_num.to_bytes_be();

        // Only pad during encryption to ensure consistent block sizes
        if matches!(mode, TransformMode::Encrypt) && output_bytes.len() < block_size {
            result.resize(result.len() + block_size - output_bytes.len(), 0);
        }

        result.extend_from_slice(&output_bytes);
    }

    // Remove leading zero padding only during decryption
    if matches!(mode, TransformMode::Decrypt) {
        let first_non_zero = result.iter().position(|&b| b != 0).unwrap_or(result.len());
        result.drain(..first_non_zero);
    }

    result
}

/// Generates a prime number of specified bit length using the Solovay-Strassen primality test.
///
/// # Arguments
///
/// * `bits` - The bit length of the prime number to generate.
/// * `iterations` - The number of iterations for the Solovay-Strassen test.
///   More iterations increase confidence in primality.
///   20 iterations provide reasonable confidence for cryptographic use.
///
/// # Returns
///
/// A `BigUint` representing a probably-prime number.
fn generate_prime(bits: u64, iterations: usize) -> BigUint {
    let mut rng = rand::thread_rng();
    loop {
        // Generate random number and ensure it's odd
        let candidate = rng.gen_biguint(bits) | BigUint::one();
        if solovay_strassen_is_prime(&candidate, iterations) {
            return candidate;
        }
    }
}

/// Performs the Solovay-Strassen primality test on a given number.
///
/// # Arguments
///
/// * `num` - The number to test for primality.
/// * `iterations` - The number of test iterations to perform.
///
/// # Returns
///
/// `true` if the number is probably prime, `false` if it is definitely composite.
fn solovay_strassen_is_prime(num: &BigUint, iterations: usize) -> bool {
    let one = BigUint::one();
    let two = &one + &one;
    let three = &two + &one;

    // Handle edge cases
    if num < &two {
        return false;
    }
    if num == &two || num == &three {
        return true;
    }
    if num.is_even() {
        return false;
    }
    
    // For very small odd numbers (just 3 at this point), already handled
    if num <= &three {
        return true;
    }

    let num_minus_one = num - &one;
    let num_minus_two = num - &two;

    // Perform the Solovay-Strassen test
    let mut rng = rand::thread_rng();
    for _ in 0..iterations {
        // Generate random integer a in the range [2, num - 2]
        let a = rng.gen_biguint_range(&two, &num_minus_two);

        // If gcd(a, num) > 1, then num is composite
        let gcd = num.gcd(&a);
        if gcd > one {
            return false;
        }

        // Compute Jacobi symbol (a/num)
        let jacobi = jacobi_symbol(&a, num);

        // Compute a^((num - 1) / 2) mod num
        let exp = &num_minus_one >> 1; // Equivalent to (num - 1) / 2
        let mod_exp = a.modpow(&exp, num);

        // Convert Jacobi symbol to BigUint for comparison
        let jacobi_mod = if jacobi == -1 {
            num_minus_one.clone()
        } else {
            jacobi.to_biguint().unwrap()
        };

        // If Jacobi symbol is not congruent to mod_exp, num is composite
        if mod_exp != jacobi_mod {
            return false;
        }
    }

    // All iterations passed, num is probably prime
    true
}

/// Computes the Jacobi symbol (a/n).
///
/// # Arguments
///
/// * `a` - The numerator as a `BigUint`.
/// * `n` - The denominator as a `BigUint` (must be an odd positive integer).
/// 
/// # Returns
///
/// An integer representing the Jacobi symbol: 1, -1, or 0.
///
/// # Panics
///
/// Panics if `n` is zero or even.
fn jacobi_symbol(a: &BigUint, n: &BigUint) -> i32 {
    if n.is_zero() || n.is_even() {
        panic!("n must be a positive odd integer");
    }
    
    let mut a = a.clone() % n;
    let mut n = n.clone();
    let mut result = 1;

    let zero = BigUint::zero();
    let one = BigUint::one();
    let two = &one + &one;
    let three = &two + &one;
    let four = &two + &two;
    let five = &four + &one;
    let eight = &four + &four;

    while a != zero {
        while a.is_even() {
            a /= &two;
            let n_mod_8 = &n % &eight;
            if n_mod_8 == three || n_mod_8 == five {
                result = -result;
            }
        }

        std::mem::swap(&mut a, &mut n);

        if &a % &four == three && &n % &four == three {
            result = -result;
        }

        a %= &n;
    }

    if n == one {
        result
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_short_message() {
        let keypair = generate_keypair(512);
        let plaintext = b"Hello, World!";
        
        let ciphertext = encrypt(plaintext, &keypair.public_key);
        let decrypted = decrypt(&ciphertext, &keypair.private_key);
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_long_message() {
        let keypair = generate_keypair(512);
        let plaintext = b"The quick brown fox jumps over the lazy dog. ".repeat(10);
        
        let ciphertext = encrypt(&plaintext, &keypair.public_key);
        let decrypted = decrypt(&ciphertext, &keypair.private_key);
        
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_empty() {
        let keypair = generate_keypair(512);
        let plaintext = b"";
        
        let ciphertext = encrypt(plaintext, &keypair.public_key);
        let decrypted = decrypt(&ciphertext, &keypair.private_key);
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_key_equality() {
        let keypair1 = generate_keypair(512);
        let keypair2 = keypair1.clone();
        
        assert_eq!(keypair1, keypair2);
    }

    #[test]
    fn test_solovay_strassen_known_primes() {
        assert!(solovay_strassen_is_prime(&BigUint::from(2u32), 1));
        assert!(solovay_strassen_is_prime(&BigUint::from(3u32), 1));
        assert!(solovay_strassen_is_prime(&BigUint::from(5u32), 1));
        assert!(solovay_strassen_is_prime(&BigUint::from(7u32), 1));
        assert!(solovay_strassen_is_prime(&BigUint::from(11u32), 1));
        assert!(solovay_strassen_is_prime(&BigUint::from(13u32), 1));
        assert!(solovay_strassen_is_prime(&BigUint::from(17u32), 1));
    }

    #[test]
    fn test_solovay_strassen_known_composites() {
        assert!(!solovay_strassen_is_prime(&BigUint::from(0u32), 1));
        assert!(!solovay_strassen_is_prime(&BigUint::from(1u32), 1));
        assert!(!solovay_strassen_is_prime(&BigUint::from(4u32), 1));
        assert!(!solovay_strassen_is_prime(&BigUint::from(6u32), 1));
        assert!(!solovay_strassen_is_prime(&BigUint::from(8u32), 1));
        assert!(!solovay_strassen_is_prime(&BigUint::from(9u32), 1));
        assert!(!solovay_strassen_is_prime(&BigUint::from(15u32), 1));
    }

    #[test]
    #[should_panic(expected = "Key size must be at least 512 bits")]
    fn test_keypair_generation_too_small() {
        generate_keypair(256);
    }

    #[test]
    #[should_panic(expected = "Key size must be even")]
    fn test_keypair_generation_odd_bits() {
        generate_keypair(513);
    }
}
