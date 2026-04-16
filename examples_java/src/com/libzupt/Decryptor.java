package com.libzupt;

/**
 * Hybrid decryption class.
 * Decrypts data using the hybrid post-quantum encryption scheme.
 */
public class Decryptor {

    static {
        System.loadLibrary("Jzupt");
    }

    private final byte[] secretKey;

    /**
     * Create a decryptor with the given secret key.
     * @param secretKey the secret key for decryption
     */
    public Decryptor(byte[] secretKey) {
        this.secretKey = secretKey != null ? secretKey.clone() : new byte[0];
    }

    /**
     * Decrypt data in memory.
     * @param ciphertext the encrypted data
     * @param encHeader the encryption header from encryption
     * @return the decrypted data
     */
    public byte[] decryptMemory(byte[] ciphertext, byte[] encHeader) {
        return decryptMemoryNative(ciphertext, encHeader);
    }

    /**
     * Decrypt data in memory to a secure buffer.
     * @param ciphertext the encrypted data
     * @param encHeader the encryption header from encryption
     * @return a secure buffer containing the decrypted data
     */
    public SecureBuffer decryptMemorySecure(byte[] ciphertext, byte[] encHeader) {
        byte[] result = decryptMemoryNative(ciphertext, encHeader);
        return new SecureBuffer(result);
    }

    /**
     * Decrypt a file.
     * @param filename the path to the encrypted file
     * @param encHeader the encryption header from encryption
     * @return the decrypted data
     */
    public byte[] decryptFile(String filename, byte[] encHeader) {
        return decryptFileNative(filename, encHeader);
    }

    // Native methods
    private native byte[] decryptMemoryNative(byte[] ciphertext, byte[] encHeader);
    private native byte[] decryptFileNative(String filename, byte[] encHeader);
}
