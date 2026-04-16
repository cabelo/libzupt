package com.libzupt;

/**
 * Hybrid encryption class.
 * Encrypts data using the hybrid post-quantum encryption scheme.
 */
public class Encryptor {

    private final byte[] publicKey;

    /**
     * Create an encryptor with the given public key.
     * @param publicKey the public key for encryption
     */
    public Encryptor(byte[] publicKey) {
        this.publicKey = publicKey != null ? publicKey.clone() : new byte[0];
    }

    /**
     * Encrypt data in memory.
     * @param data the data to encrypt
     * @return a tuple containing (ciphertext, encryption header)
     */
    public Object[] encryptMemory(byte[] data) {
        return nativeEncryptMemory(data);
    }

    /**
     * Encrypt data in memory using a secure buffer.
     * @param buffer the secure buffer containing data
     * @return a tuple containing (ciphertext, encryption header)
     */
    public Object[] encryptMemorySecure(SecureBuffer buffer) {
        return nativeEncryptMemory(buffer.toBytes());
    }

    /**
     * Encrypt a file.
     * @param filename the path to the file to encrypt
     * @return a tuple containing (ciphertext, encryption header)
     */
    public Object[] encryptFile(String filename) {
        return nativeEncryptFile(filename);
    }

    /**
     * Get the encryption header size.
     * @return the header size in bytes
     */
    public static int getHeaderSize() {
        return 1137; // HYBRID_ENC_HEADER_SIZE
    }

    // Native methods
    private native Object[] nativeEncryptMemory(byte[] data);
    private native Object[] nativeEncryptFile(String filename);
}