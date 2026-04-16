package com.libzupt;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * File Encryption/Decryption Example.
 * Shows how to encrypt and decrypt files.
 */
public class ExampleFile {

    public static void main(String[] args) throws IOException {
        System.out.println("=".repeat(60));
        System.out.println("libzupt - File Encryption/Decryption Example");
        System.out.println("=".repeat(60));
        System.out.println();

        // Generate key pair
        System.out.println("1. Generating key pair...");
        KeyGenerator keygen = new KeyGenerator();
        KeyPair keypair = keygen.generateKeyPair();
        System.out.println("   Key pair generated");
        System.out.println();

        // Create temporary test file
        Path tempDir = Files.createTempDirectory("zupt_test");
        Path testFile = tempDir.resolve("test.txt");
        Path cipherFile = tempDir.resolve("test.txt.enc");

        try {
            String originalContent =
                "This is a secret text file.\n" +
                "Line 2: Contains sensitive information.\n" +
                "Line 3: End of file.\n";
            Files.writeString(testFile, originalContent);

            System.out.println("2. Created test file: " + testFile);
            System.out.println("   Original content:");
            System.out.println(originalContent);

            // Encrypt file
            Encryptor encryptor = new Encryptor(keypair.publicKey);
            Object[] encrypted = encryptor.encryptFile(testFile.toString());
            byte[] ciphertext = (byte[]) encrypted[0];
            byte[] encHeader = (byte[]) encrypted[1];

            System.out.println("3. Encrypting file...");
            System.out.println("   Ciphertext size: " + ciphertext.length + " bytes");
            System.out.println("   Header size: " + encHeader.length + " bytes");
            System.out.println();

            // Save ciphertext
            Files.write(cipherFile, ciphertext);
            System.out.println("4. Saved ciphertext to: " + cipherFile);
            System.out.println();

            // Decrypt file
            Decryptor decryptor = new Decryptor(keypair.secretKey);
            byte[] decrypted = decryptor.decryptFile(cipherFile.toString(), encHeader);
            String decryptedContent = new String(decrypted);

            System.out.println("5. Decrypting file...");
            System.out.println("   Decrypted size: " + decrypted.length + " bytes");
            System.out.println("   Decrypted content:");
            System.out.println(decryptedContent);

            // Verify
            if (!originalContent.equals(decryptedContent)) {
                throw new RuntimeException("Decryption failed!");
            }
            System.out.println();

            System.out.println("6. Cleaned up temporary files");

        } finally {
            // Cleanup
            try {
                Files.deleteIfExists(cipherFile);
                Files.deleteIfExists(testFile);
                Files.deleteIfExists(tempDir);
            } catch (IOException e) {
                // Ignore cleanup errors
            }
        }

        System.out.println("=".repeat(60));
        System.out.println("File encryption/decryption example passed!");
        System.out.println("=".repeat(60));
    }
}