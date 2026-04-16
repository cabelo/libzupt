package com.libzupt;

import java.util.Formatter;

/**
 * Random Bytes and Hashing Example.
 * Shows random number generation and hashing functions.
 */
public class ExampleRandom {

    public static void main(String[] args) {
        System.out.println("=".repeat(60));
        System.out.println("libzupt - Random Bytes and Hashing Example");
        System.out.println("=".repeat(60));
        System.out.println();

        // Generate random bytes
        System.out.println("1. Generating random bytes...");
        byte[] randomBytes = NativeLib.randomBytes(32);
        System.out.println("   Generated 32 random bytes:");
        System.out.println("   " + bytesToHex(randomBytes));
        System.out.println();

        // Generate AES nonce
        System.out.println("2. Generating AES nonce...");
        byte[] nonce = NativeLib.randomBytes(16);
        System.out.println("   Nonce (16 bytes): " + bytesToHex(nonce));
        System.out.println();

        // Compute SHA-256 hash
        System.out.println("3. Computing SHA-256 hash...");
        byte[] data = "Hello, Post-Quantum World!".getBytes();
        byte[] sha256Hash = NativeLib.sha256(data);
        System.out.println("   Data: " + new String(data));
        System.out.println("   SHA-256: " + bytesToHex(sha256Hash));
        System.out.println();

        // Compute SHA3-512 hash
        System.out.println("4. Computing SHA3-512 hash...");
        byte[] sha3_512Hash = NativeLib.sha3512(data);
        System.out.println("   Data: " + new String(data));
        System.out.println("   SHA3-512: " + bytesToHex(sha3_512Hash));
        System.out.println();

        // Simulate key derivation
        System.out.println("5. Simulating key derivation...");
        byte[] salt = NativeLib.randomBytes(16);
        byte[] password = "my-password".getBytes();
        // Simple KDF simulation: SHA256(salt || password)
        byte[] combined = new byte[salt.length + password.length];
        System.arraycopy(salt, 0, combined, 0, salt.length);
        System.arraycopy(password, 0, combined, salt.length, password.length);
        byte[] derivedKey = NativeLib.sha256(combined);

        System.out.println("   Salt: " + bytesToHex(salt));
        System.out.println("   Derived key (32 bytes): " + bytesToHex(derivedKey));
        System.out.println();

        System.out.println("=".repeat(60));
        System.out.println("Random bytes and hashing example passed!");
        System.out.println("=".repeat(60));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}