package com.libzupt;

/**
 * Native library helper functions.
 */
public class NativeLib {

    static {
        System.loadLibrary("Jzupt");
    }

    /**

    /**
     * Generate random bytes.
     * @param size the number of bytes to generate
     * @return the random bytes
     */
    public static native byte[] randomBytes(int size);

    /**
     * Compute SHA-256 hash.
     * @param data the data to hash
     * @return the 32-byte hash
     */
    public static native byte[] sha256(byte[] data);

    /**
     * Compute SHA3-512 hash.
     * @param data the data to hash
     * @return the 64-byte hash
     */
    public static native byte[] sha3512(byte[] data);
}
