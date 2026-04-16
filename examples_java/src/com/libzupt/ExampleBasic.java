package com.libzupt;

/**
 * Basic Encryption/Decryption Example.
 * Shows how to use the library for basic memory encryption/decryption.
 */
public class ExampleBasic {

    static {
        System.loadLibrary("Jzupt");
    }

    public static void main(String[] args) {
        System.out.println("=".repeat(60));
        System.out.println("libzupt - Basic Encryption/Decryption Example");
        System.out.println("=".repeat(60));
        System.out.println();

        // Generate key pair
        System.out.println("1. Generating key pair...");
        KeyGenerator keygen = new KeyGenerator();
        KeyPair keypair = keygen.generateKeyPair();
        System.out.println("   Public key size: " + keypair.publicKey.length + " bytes");
        System.out.println("   Secret key size: " + keypair.secretKey.length + " bytes");
        System.out.println();

        // Create encryptor and decryptor
        Encryptor encryptor = new Encryptor(keypair.publicKey);
        Decryptor decryptor = new Decryptor(keypair.secretKey);

        // Encrypt some data
        byte[] message = "Hello, Post-Quantum World! This is a secret message.".getBytes();
        System.out.println("2. Encrypting message: " + new String(message));
        Object[] encrypted = encryptor.encryptMemory(message);
        byte[] ciphertext = (byte[]) encrypted[0];
        byte[] encHeader = (byte[]) encrypted[1];
        System.out.println("   Ciphertext size: " + ciphertext.length + " bytes");
        System.out.println("   Header size: " + encHeader.length + " bytes");
        System.out.println();

        // Decrypt
        System.out.println("3. Decrypting...");
        byte[] decrypted = decryptor.decryptMemory(ciphertext, encHeader);
        System.out.println("   Decrypted: " + new String(decrypted));
        System.out.println();

        // Verify
        if (!java.util.Arrays.equals(decrypted, message)) {
            throw new RuntimeException("Decryption failed!");
        }
        System.out.println("4. Verification: SUCCESS - Decrypted message matches original");
        System.out.println();

        // Demonstrate error with wrong key
        System.out.println("5. Testing with wrong key...");
        KeyGenerator keygen2 = new KeyGenerator();
        KeyPair keypair2 = keygen2.generateKeyPair();
        Decryptor decryptorWrong = new Decryptor(keypair2.secretKey);

        try {
            decryptorWrong.decryptMemory(ciphertext, encHeader);
            System.out.println("   ERROR: Should have failed!");
        } catch (ZuptError e) {
            System.out.println("   Correctly rejected with error: " + e.getMessage());
        }
        System.out.println();

        System.out.println("=".repeat(60));
        System.out.println("All examples passed!");
        System.out.println("=".repeat(60));
    }
}
