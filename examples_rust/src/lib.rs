#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unused_imports)]

mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use std::fmt;

pub use bindings::*;

pub const MLKEM_PUBLICKEYBYTES: usize = 1184;
pub const MLKEM_SECRETKEYBYTES: usize = 2400;
pub const MLKEM_CIPHERTEXTBYTES: usize = 1088;
pub const MLKEM_SSBYTES: usize = 32;
pub const X25519_KEYBYTES: usize = 32;
pub const HYBRID_PUB_KEY_SIZE: usize = 1224;
pub const HYBRID_PRIV_KEY_SIZE: usize = 3656;
pub const HYBRID_ENC_HEADER_SIZE: usize = 1137;
pub const AES_KEY_SIZE: usize = 32;
pub const AES_NONCE_SIZE: usize = 16;
pub const HMAC_SIZE: usize = 32;

#[derive(Debug, Clone)]
pub struct ZuptError {
    message: String,
}

impl fmt::Display for ZuptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ZuptError {}

impl ZuptError {
    fn from_str(msg: &str) -> Self {
        Self { message: msg.to_string() }
    }
}

pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl KeyPair {
    pub fn new() -> Self {
        Self {
            public_key: vec![0u8; HYBRID_PUB_KEY_SIZE],
            secret_key: vec![0u8; HYBRID_PRIV_KEY_SIZE],
        }
    }
}

pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    pub fn from_bytes(data: &[u8]) -> Self {
        Self { data: data.to_vec() }
    }

    pub fn new(size: usize) -> Self {
        Self { data: vec![0u8; size] }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn to_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.data).to_string()
    }

    pub fn zeroize(&mut self) {
        for byte in self.data.iter_mut() {
            *byte = 0;
        }
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub fn generate_keypair() -> Result<KeyPair, ZuptError> {
    let mut kp = KeyPair::new();
    let ret = unsafe {
        bindings::zupt_hybrid_keygen_c(
            kp.public_key.as_mut_ptr(),
            kp.secret_key.as_mut_ptr(),
        )
    };
    if ret != 0 {
        return Err(ZuptError::from_str("Failed to generate key pair"));
    }
    Ok(kp)
}

pub fn export_public_key(priv_key: &[u8], pub_key: &mut [u8]) -> Result<(), ZuptError> {
    if priv_key.len() < HYBRID_PRIV_KEY_SIZE {
        return Err(ZuptError::from_str("Private key too short"));
    }
    if pub_key.len() < HYBRID_PUB_KEY_SIZE {
        return Err(ZuptError::from_str("Public key buffer too short"));
    }
    let ret = unsafe {
        bindings::zupt_hybrid_export_pubkey_c(priv_key.as_ptr(), pub_key.as_mut_ptr())
    };
    if ret != 0 {
        return Err(ZuptError::from_str("Failed to export public key"));
    }
    Ok(())
}

pub fn encrypt(pub_key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ZuptError> {
    let mut enc_header = vec![0u8; HYBRID_ENC_HEADER_SIZE];
    let mut enc_header_len = enc_header.len();
    let mut ciphertext_len: usize = 0;

    let ciphertext = unsafe {
        bindings::zupt_hybrid_encrypt(
            pub_key.as_ptr(),
            pub_key.len(),
            plaintext.as_ptr(),
            plaintext.len(),
            enc_header.as_mut_ptr(),
            &mut enc_header_len,
            &mut ciphertext_len,
        )
    };

    if ciphertext.is_null() {
        return Err(ZuptError::from_str("Encryption failed"));
    }

    let ct = unsafe { Vec::from_raw_parts(ciphertext, ciphertext_len, ciphertext_len) };
    enc_header.truncate(enc_header_len);
    Ok((ct, enc_header))
}

pub fn decrypt(priv_key: &[u8], ciphertext: &[u8], enc_header: &[u8]) -> Result<Vec<u8>, ZuptError> {
    let mut plaintext_len: usize = 0;

    let plaintext = unsafe {
        bindings::zupt_hybrid_decrypt(
            priv_key.as_ptr(),
            priv_key.len(),
            ciphertext.as_ptr(),
            ciphertext.len(),
            enc_header.as_ptr(),
            enc_header.len(),
            &mut plaintext_len,
        )
    };

    if plaintext.is_null() {
        return Err(ZuptError::from_str("Decryption failed (wrong key or corrupted data)"));
    }

    Ok(unsafe { Vec::from_raw_parts(plaintext, plaintext_len, plaintext_len) })
}

pub fn encrypt_file(pub_key: &[u8], path: &str) -> Result<(Vec<u8>, Vec<u8>), ZuptError> {
    let c_path = std::ffi::CString::new(path)
        .map_err(|_| ZuptError::from_str("Invalid file path"))?;
    let mut size: usize = 0;
    let data = unsafe { bindings::zupt_read_file(c_path.as_ptr(), &mut size) };
    if data.is_null() {
        return Err(ZuptError::from_str("Failed to read file"));
    }
    let plaintext = unsafe { Vec::from_raw_parts(data, size, size) };
    encrypt(pub_key, &plaintext)
}

pub fn decrypt_file(priv_key: &[u8], path: &str, enc_header: &[u8]) -> Result<Vec<u8>, ZuptError> {
    let c_path = std::ffi::CString::new(path)
        .map_err(|_| ZuptError::from_str("Invalid file path"))?;
    let mut size: usize = 0;
    let data = unsafe { bindings::zupt_read_file(c_path.as_ptr(), &mut size) };
    if data.is_null() {
        return Err(ZuptError::from_str("Failed to read file"));
    }
    let ciphertext = unsafe { Vec::from_raw_parts(data, size, size) };
    decrypt(priv_key, &ciphertext, enc_header)
}

pub fn random_bytes(count: usize) -> Vec<u8> {
    let mut buf = vec![0u8; count];
    unsafe {
        bindings::zupt_random_bytes(buf.as_mut_ptr(), buf.len());
    }
    buf
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    unsafe {
        bindings::zupt_sha256(data.as_ptr(), data.len(), out.as_mut_ptr());
    }
    out
}

pub fn sha3_512(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 64];
    unsafe {
        bindings::zupt_sha3_512(data.as_ptr(), data.len(), out.as_mut_ptr());
    }
    out
}

pub fn secure_wipe(buf: &mut [u8]) {
    unsafe {
        let ptr = buf.as_mut_ptr();
        let len = buf.len();
        for i in 0..len {
            std::ptr::write_volatile(ptr.add(i), 0u8);
        }
    }
}

pub fn save_keypair(kp: &KeyPair, path: &str) -> Result<(), ZuptError> {
    let c_path = std::ffi::CString::new(path)
        .map_err(|_| ZuptError::from_str("Invalid file path"))?;
    let ret = unsafe {
        bindings::zupt_write_file(c_path.as_ptr(), kp.secret_key.as_ptr(), kp.secret_key.len())
    };
    if ret != 0 {
        return Err(ZuptError::from_str("Failed to save key pair"));
    }
    Ok(())
}

pub fn load_keypair(path: &str) -> Result<KeyPair, ZuptError> {
    let c_path = std::ffi::CString::new(path)
        .map_err(|_| ZuptError::from_str("Invalid file path"))?;
    let mut size: usize = 0;
    let data = unsafe { bindings::zupt_read_file(c_path.as_ptr(), &mut size) };
    if data.is_null() {
        return Err(ZuptError::from_str("Failed to read key file"));
    }
    let file_data = unsafe { Vec::from_raw_parts(data, size, size) };

    if size < HYBRID_PRIV_KEY_SIZE {
        return Err(ZuptError::from_str("Key file too small"));
    }

    let mut pub_key = vec![0u8; HYBRID_PUB_KEY_SIZE];
    export_public_key(&file_data, &mut pub_key)?;

    Ok(KeyPair {
        public_key: pub_key,
        secret_key: file_data,
    })
}

pub fn load_public_key(path: &str) -> Result<Vec<u8>, ZuptError> {
    let c_path = std::ffi::CString::new(path)
        .map_err(|_| ZuptError::from_str("Invalid file path"))?;
    let mut size: usize = 0;
    let data = unsafe { bindings::zupt_read_file(c_path.as_ptr(), &mut size) };
    if data.is_null() {
        return Err(ZuptError::from_str("Failed to read key file"));
    }
    let file_data = unsafe { Vec::from_raw_parts(data, size, size) };

    if file_data.len() < HYBRID_PUB_KEY_SIZE {
        return Err(ZuptError::from_str("Key file too small for public key"));
    }

    let mut pub_key = vec![0u8; HYBRID_PUB_KEY_SIZE];
    pub_key.copy_from_slice(&file_data[..HYBRID_PUB_KEY_SIZE]);
    Ok(pub_key)
}

pub fn write_file(path: &str, data: &[u8]) -> Result<(), ZuptError> {
    let c_path = std::ffi::CString::new(path)
        .map_err(|_| ZuptError::from_str("Invalid file path"))?;
    let ret = unsafe {
        bindings::zupt_write_file(c_path.as_ptr(), data.as_ptr(), data.len())
    };
    if ret != 0 {
        return Err(ZuptError::from_str("Failed to write file"));
    }
    Ok(())
}

pub fn read_file(path: &str) -> Result<Vec<u8>, ZuptError> {
    let c_path = std::ffi::CString::new(path)
        .map_err(|_| ZuptError::from_str("Invalid file path"))?;
    let mut size: usize = 0;
    let data = unsafe { bindings::zupt_read_file(c_path.as_ptr(), &mut size) };
    if data.is_null() {
        return Err(ZuptError::from_str("Failed to read file"));
    }
    Ok(unsafe { Vec::from_raw_parts(data, size, size) })
}
