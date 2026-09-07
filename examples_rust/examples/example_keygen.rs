use libzupt_rust;
use std::fs;

fn main() {
    println!("{}", "=".repeat(60));
    println!("libzupt - Key Generation and Management Example (Rust)");
    println!("{}", "=".repeat(60));
    println!();

    let tmpdir = "rust_zupt_test_keys";
    fs::create_dir_all(tmpdir).expect("Failed to create temp dir");
    let priv_key_file = format!("{}/private.key", tmpdir);
    let pub_key_file = format!("{}/public.key", tmpdir);

    println!("1. Generating key pair...");
    let keypair = libzupt_rust::generate_keypair().expect("Failed to generate key pair");
    println!("   Public key: {} bytes", keypair.public_key.len());
    println!("   Private key: {} bytes", keypair.secret_key.len());
    println!();

    println!("2. Saving key pair...");
    libzupt_rust::save_keypair(&keypair, &priv_key_file).expect("Failed to save key pair");
    println!("   Saved to: {}", priv_key_file);
    println!();

    println!("3. Exporting public key...");
    let mut exported_pub = vec![0u8; libzupt_rust::HYBRID_PUB_KEY_SIZE];
    libzupt_rust::export_public_key(&keypair.secret_key, &mut exported_pub)
        .expect("Failed to export public key");
    libzupt_rust::write_file(&pub_key_file, &exported_pub).expect("Failed to write public key");
    println!("   Saved to: {}", pub_key_file);
    println!();

    println!("4. Loading key pair...");
    let loaded_kp = libzupt_rust::load_keypair(&priv_key_file).expect("Failed to load key pair");
    println!("   Loaded public key: {} bytes", loaded_kp.public_key.len());
    println!("   Loaded private key: {} bytes", loaded_kp.secret_key.len());
    assert_eq!(loaded_kp.public_key, keypair.public_key);
    assert_eq!(loaded_kp.secret_key, keypair.secret_key);
    println!("   Keys match!");
    println!();

    println!("5. Loading public key only...");
    let loaded_pub = libzupt_rust::load_public_key(&pub_key_file).expect("Failed to load public key");
    println!("   Loaded public key: {} bytes", loaded_pub.len());
    assert_eq!(loaded_pub, keypair.public_key);
    println!("   Public key matches!");
    println!();

    println!("6. Key sizes (bytes):");
    println!("   ML-KEM public key: {}", libzupt_rust::MLKEM_PUBLICKEYBYTES);
    println!("   X25519 public key: {}", libzupt_rust::X25519_KEYBYTES);
    println!("   Hybrid public key: {}", libzupt_rust::HYBRID_PUB_KEY_SIZE);
    println!("   Hybrid private key: {}", libzupt_rust::HYBRID_PRIV_KEY_SIZE);
    println!("   Encryption header: {}", libzupt_rust::HYBRID_ENC_HEADER_SIZE);
    println!();

    fs::remove_dir_all(tmpdir).ok();

    println!("{}", "=".repeat(60));
    println!("Key management example passed!");
    println!("{}", "=".repeat(60));
}
