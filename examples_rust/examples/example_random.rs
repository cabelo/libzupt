use libzupt_rust;

fn main() {
    println!("{}", "=".repeat(60));
    println!("libzupt - Random Bytes and Hashing Example (Rust)");
    println!("{}", "=".repeat(60));
    println!();

    println!("1. Generating random bytes...");
    let random_bytes = libzupt_rust::random_bytes(32);
    println!("   Generated {} random bytes:", random_bytes.len());
    println!("   {}", hex::encode(&random_bytes));
    println!();

    println!("2. Generating AES nonce...");
    let nonce = libzupt_rust::random_bytes(libzupt_rust::AES_NONCE_SIZE);
    println!("   Nonce ({} bytes): {}", nonce.len(), hex::encode(&nonce));
    println!();

    let data = b"Hello, Post-Quantum World!";

    println!("3. Computing SHA-256 hash...");
    let sha256_hash = libzupt_rust::sha256(data);
    println!("   Data: {}", String::from_utf8_lossy(data));
    println!("   SHA-256: {}", hex::encode(&sha256_hash));
    println!();

    println!("4. Computing SHA3-512 hash...");
    let sha3_512_hash = libzupt_rust::sha3_512(data);
    println!("   Data: {}", String::from_utf8_lossy(data));
    println!("   SHA3-512: {}", hex::encode(&sha3_512_hash));
    println!();

    println!("5. Simulating key derivation...");
    let salt = libzupt_rust::random_bytes(16);
    println!("   Salt: {}", hex::encode(&salt));
    let mut input = salt.clone();
    input.extend_from_slice(b"my-secret-password");
    let derived_key = libzupt_rust::sha256(&input);
    println!("   Derived key (32 bytes): {}", hex::encode(&derived_key));
    println!();

    println!("{}", "=".repeat(60));
    println!("Random bytes and hashing example passed!");
    println!("{}", "=".repeat(60));
}
