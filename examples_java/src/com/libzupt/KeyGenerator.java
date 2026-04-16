package com.libzupt;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Key generation and management.
 * Generates and manages hybrid post-quantum key pairs.
 */
public class KeyGenerator {

    static {
        System.loadLibrary("Jzupt");
    }

    /**

    /**
     * Generate a new hybrid key pair (ML-KEM-768 + X25519).
     * @return the generated key pair
     */
    public native KeyPair generateKeyPair();

    /**
     * Load a key pair from a file.
     * @param filename the path to the key file
     * @return the loaded key pair
     */
    public native KeyPair loadKeyPair(String filename);

    /**
     * Load a public key only from a file.
     * @param filename the path to the public key file
     * @return the public key bytes
     */
    public native byte[] loadPublicKey(String filename);

    /**
     * Export only the public key from a private key file.
     * @param privFile the path to the private key file
     * @param pubFile the path where to save the public key
     */
    public native void exportPublicKey(String privFile, String pubFile);

    /**
     * Save a key pair to a file.
     * @param keyPair the key pair to save
     * @param filename the path where to save the key pair
     */
    public native void saveKeyPair(KeyPair keyPair, String filename);
}
