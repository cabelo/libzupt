use libzupt_rust;
use std::fs;
use std::io::Write;

fn main() {
    println!("{}", "=".repeat(60));
    println!("libzupt - File Encryption/Decryption Example (Rust)");
    println!("{}", "=".repeat(60));
    println!();

    println!("1. Generating key pair...");
    let keypair = libzupt_rust::generate_keypair().expect("Failed to generate key pair");
    println!("   Key pair generated");
    println!();

    let test_content = b"This is a secret text file.\nLine 2: Contains sensitive information.\nLine 3: End of file.\n";
    let test_path = "rust_test_file.txt";
    let cipher_path = "rust_test_file.txt.enc";

    {
        let mut f = fs::File::create(test_path).expect("Failed to create test file");
        f.write_all(test_content).expect("Failed to write test file");
    }
    println!("2. Created test file: {}", test_path);
    println!("   Original content:\n{}", String::from_utf8_lossy(test_content));

    println!("3. Encrypting file...");
    let (ciphertext, enc_header) =
        libzupt_rust::encrypt_file(&keypair.public_key, test_path).expect("Failed to encrypt file");
    println!("   Ciphertext size: {} bytes", ciphertext.len());
    println!("   Header size: {} bytes", enc_header.len());
    println!();

    libzupt_rust::write_file(cipher_path, &ciphertext).expect("Failed to write cipher file");
    println!("4. Saved ciphertext to: {}", cipher_path);
    println!();

    println!("5. Decrypting file...");
    let decrypted = libzupt_rust::decrypt_file(&keypair.secret_key, cipher_path, &enc_header)
        .expect("Failed to decrypt file");
    println!("   Decrypted size: {} bytes", decrypted.len());
    println!(
        "   Decrypted content:\n{}",
        String::from_utf8_lossy(&decrypted)
    );

    assert_eq!(decrypted, test_content, "Decryption failed!");
    println!();

    fs::remove_file(test_path).ok();
    fs::remove_file(cipher_path).ok();
    println!("6. Cleaned up temporary files");
    println!();

    println!("{}", "=".repeat(60));
    println!("File encryption/decryption example passed!");
    println!("{}", "=".repeat(60));
}
