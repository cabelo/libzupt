use libzupt_rust::SecureBuffer;

fn main() {
    println!("{}", "=".repeat(60));
    println!("libzupt - SecureBuffer Example (Rust)");
    println!("{}", "=".repeat(60));
    println!();

    println!("1. Creating SecureBuffer from bytes...");
    let secret = b"My secret password123";
    let mut buffer = SecureBuffer::from_bytes(secret);
    println!("   Buffer size: {} bytes", buffer.len());
    println!("   Buffer content: {}", buffer.to_string_lossy());
    println!();

    println!("2. Creating empty SecureBuffer...");
    let empty_buffer = SecureBuffer::new(64);
    println!("   Empty buffer size: {} bytes", empty_buffer.len());
    println!();

    println!("3. Encrypting with SecureBuffer...");
    let keypair = libzupt_rust::generate_keypair().expect("Failed to generate key pair");
    let (ciphertext, enc_header) =
        libzupt_rust::encrypt(&keypair.public_key, buffer.as_slice()).expect("Failed to encrypt");
    println!("   Ciphertext size: {} bytes", ciphertext.len());
    println!();

    println!("4. Decrypting to SecureBuffer...");
    let decrypted_data =
        libzupt_rust::decrypt(&keypair.secret_key, &ciphertext, &enc_header).expect("Failed to decrypt");
    let decrypted_buffer = SecureBuffer::from_bytes(&decrypted_data);
    println!("   Decrypted buffer size: {} bytes", decrypted_buffer.len());
    println!("   Decrypted content: {}", decrypted_buffer.to_string_lossy());
    println!();

    assert_eq!(decrypted_buffer.as_slice(), secret);
    println!("5. Verification: SUCCESS");
    println!();

    println!("6. Securely wiping buffer...");
    buffer.zeroize();
    println!("   Buffer zeroized (content is now zero)");
    println!();

    println!("{}", "=".repeat(60));
    println!("SecureBuffer example passed!");
    println!("{}", "=".repeat(60));
}
