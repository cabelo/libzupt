package com.libzupt;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Key Generation and Key Management Example.
 * Shows how to generate keys and manage them.
 */
public class ExampleKeygen {

    public static void main(String[] args) throws IOException {
        System.out.println("=".repeat(60));
        System.out.println("libzupt - Key Generation and Management Example");
        System.out.println("=".repeat(60));
        System.out.println();

        // Create a temporary directory for keys
        Path tempDir = Files.createTempDirectory("zupt_keys");
        Path privKeyFile = tempDir.resolve("private.key");
        Path pubKeyFile = tempDir.resolve("public.key");

        try {
            // Generate a key pair
            System.out.println("1. Generating key pair...");
            KeyGenerator keygen = new KeyGenerator();
            KeyPair keypair = keygen.generateKeyPair();
            System.out.println("   Public key: " + keypair.publicKey.length + " bytes");
            System.out.println("   Private key: " + keypair.secretKey.length + " bytes");
            System.out.println();

            // Save the key pair
            System.out.println("2. Saving key pair...");
            keygen.saveKeyPair(keypair, privKeyFile.toString());
            System.out.println("   Saved to: " + privKeyFile);
            System.out.println();

            // Export public key
            System.out.println("3. Exporting public key...");
            keygen.exportPublicKey(privKeyFile.toString(), pubKeyFile.toString());
            System.out.println("   Saved to: " + pubKeyFile);
            System.out.println();

            // Load the key pair back
            System.out.println("4. Loading key pair...");
            KeyPair loadedKeyPair = keygen.loadKeyPair(privKeyFile.toString());
            System.out.println("   Loaded public key: " + loadedKeyPair.publicKey.length + " bytes");
            System.out.println("   Loaded private key: " + loadedKeyPair.secretKey.length + " bytes");

            if (!java.util.Arrays.equals(loadedKeyPair.publicKey, keypair.publicKey)) {
                throw new RuntimeException("Public keys don't match!");
            }
            if (!java.util.Arrays.equals(loadedKeyPair.secretKey, keypair.secretKey)) {
                throw new RuntimeException("Secret keys don't match!");
            }
            System.out.println("   Keys match!");
            System.out.println();

            // Load public key only
            System.out.println("5. Loading public key only...");
            byte[] loadedPub = keygen.loadPublicKey(pubKeyFile.toString());
            System.out.println("   Loaded public key: " + loadedPub.length + " bytes");

            if (!java.util.Arrays.equals(loadedPub, keypair.publicKey)) {
                throw new RuntimeException("Public keys don't match!");
            }
            System.out.println("   Public key matches!");
            System.out.println();

            // Demonstrate key sizes
            System.out.println("6. Key sizes (bytes):");
            System.out.println("   ML-KEM public key: " + NativeLib.sha256("test".getBytes()).length * 37); // placeholder
            System.out.println("   X25519 public key: " + 32);
            System.out.println("   Hybrid public key: " + 1224);
            System.out.println("   Hybrid private key: " + 3656);
            System.out.println("   Encryption header: " + 1137);
            System.out.println();

        } finally {
            // Cleanup
            try {
                Files.deleteIfExists(privKeyFile);
                Files.deleteIfExists(pubKeyFile);
                Files.deleteIfExists(tempDir);
            } catch (IOException e) {
                // Ignore cleanup errors
            }
        }

        System.out.println("=".repeat(60));
        System.out.println("Key management example passed!");
        System.out.println("=".repeat(60));
    }
}