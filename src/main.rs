mod rsa_test;

use std::fs;

fn main() {
    // Generate a small RSA keypair for testing
    let keypair = rsa_test::generate_keypair(512);

    // Read plaintext from file
    let plaintext = fs::read("text/text00.txt").expect("Failed to read plaintext file");

    // Encrypt the plaintext
    let ciphertext = rsa_test::encrypt(&plaintext, &keypair.public_key);

    // Display the ciphertext hex
    println!("Encrypted ciphertext: {}", hex::encode(&ciphertext));

    // Decrypt the ciphertext
    let decrypted_plaintext = rsa_test::decrypt(&ciphertext, &keypair.private_key);

    // Display the decrypted plaintext
    println!(
        "Decrypted plaintext: {}",
        String::from_utf8(decrypted_plaintext).unwrap()
    );
}
