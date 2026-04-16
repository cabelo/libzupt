package com.libzupt;

/**
 * A key pair containing public and private keys.
 */
public class KeyPair {
    /** Public key bytes */
    public final byte[] publicKey;
    /** Secret (private) key bytes */
    public final byte[] secretKey;

    /**
     * Create a new key pair.
     * @param publicKey the public key
     * @param secretKey the secret key
     */
    public KeyPair(byte[] publicKey, byte[] secretKey) {
        this.publicKey = publicKey != null ? publicKey.clone() : new byte[0];
        this.secretKey = secretKey != null ? secretKey.clone() : new byte[0];
    }

    /**
     * Default constructor for JNI.
     */
    public KeyPair() {
        this.publicKey = new byte[0];
        this.secretKey = new byte[0];
    }
}