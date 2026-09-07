use libzupt_rust;

fn main() {
    println!("{}", "=".repeat(60));
    println!("libzupt - Basic Encryption/Decryption Example (Rust)");
    println!("{}", "=".repeat(60));
    println!();

    println!("1. Generating key pair...");
    let keypair = libzupt_rust::generate_keypair().expect("Failed to generate key pair");
    println!("   Public key size: {} bytes", keypair.public_key.len());
    println!("   Secret key size: {} bytes", keypair.secret_key.len());
    println!();

    let message = b"Hello, Post-Quantum World! This is a secret message.";
    println!("2. Encrypting message: {}", String::from_utf8_lossy(message));
    let (ciphertext, enc_header) = libzupt_rust::encrypt(&keypair.public_key, message)
        .expect("Failed to encrypt");
    println!("   Ciphertext size: {} bytes", ciphertext.len());
    println!("   Header size: {} bytes", enc_header.len());
    println!();

    println!("3. Decrypting...");
    let decrypted = libzupt_rust::decrypt(&keypair.secret_key, &ciphertext, &enc_header)
        .expect("Failed to decrypt");
    println!("   Decrypted: {}", String::from_utf8_lossy(&decrypted));
    println!();

    assert_eq!(decrypted, message, "Decryption failed!");
    println!("4. Verification: SUCCESS - Decrypted message matches original");
    println!();

    println!("5. Testing with wrong key...");
    let keypair2 = libzupt_rust::generate_keypair().expect("Failed to generate key pair");
    match libzupt_rust::decrypt(&keypair2.secret_key, &ciphertext, &enc_header) {
        Ok(_) => println!("   ERROR: Should have failed!"),
        Err(e) => println!("   Correctly rejected with error: {}", e),
    }
    println!();

    println!("{}", "=".repeat(60));
    println!("All examples passed!");
    println!("{}", "=".repeat(60));
}
