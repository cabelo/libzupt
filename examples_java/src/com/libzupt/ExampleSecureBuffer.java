package com.libzupt;

/**
 * SecureBuffer Example.
 * Shows how to use SecureBuffer for sensitive data.
 */
public class ExampleSecureBuffer {

    public static void main(String[] args) {
        System.out.println("=".repeat(60));
        System.out.println("libzupt - SecureBuffer Example");
        System.out.println("=".repeat(60));
        System.out.println();

        // Create SecureBuffer from bytes
        System.out.println("1. Creating SecureBuffer from bytes...");
        byte[] secret = "My secret password123".getBytes();
        SecureBuffer buffer = new SecureBuffer(secret);
        System.out.println("   Buffer size: " + buffer.size() + " bytes");
        System.out.println("   Buffer content: " + buffer.toString());
        System.out.println();

        // Create empty SecureBuffer
        System.out.println("2. Creating empty SecureBuffer...");
        SecureBuffer emptyBuffer = new SecureBuffer(64);
        System.out.println("   Empty buffer size: " + emptyBuffer.size() + " bytes");
        System.out.println();

        // Encrypt with SecureBuffer
        System.out.println("3. Encrypting with SecureBuffer...");
        KeyGenerator keygen = new KeyGenerator();
        KeyPair keypair = keygen.generateKeyPair();
        Encryptor encryptor = new Encryptor(keypair.publicKey);
        Decryptor decryptor = new Decryptor(keypair.secretKey);

        Object[] encrypted = encryptor.encryptMemorySecure(buffer);
        byte[] ciphertext = (byte[]) encrypted[0];
        byte[] encHeader = (byte[]) encrypted[1];
        System.out.println("   Ciphertext size: " + ciphertext.length + " bytes");
        System.out.println();

        // Decrypt to SecureBuffer
        System.out.println("4. Decrypting to SecureBuffer...");
        SecureBuffer decryptedBuffer = decryptor.decryptMemorySecure(ciphertext, encHeader);
        System.out.println("   Decrypted buffer size: " + decryptedBuffer.size() + " bytes");
        System.out.println("   Decrypted content: " + decryptedBuffer.toString());
        System.out.println();

        // Verify
        if (!java.util.Arrays.equals(decryptedBuffer.toBytes(), secret)) {
            throw new RuntimeException("Verification failed!");
        }
        System.out.println("5. Verification: SUCCESS");
        System.out.println();

        // Demonstrate secure wiping
        System.out.println("6. Securely wiping buffer...");
        buffer.zeroize();
        System.out.println("   Buffer zeroized (content is now zero)");
        System.out.println();

        // Close buffers (auto-zeroize)
        System.out.println("7. Closing buffers (auto-zeroize)...");
        try (SecureBuffer sb = new SecureBuffer("Sensitive data".getBytes())) {
            System.out.println("   Buffer created and used");
        }
        System.out.println("   Buffer automatically zeroized on close");
        System.out.println();

        System.out.println("=".repeat(60));
        System.out.println("SecureBuffer example passed!");
        System.out.println("=".repeat(60));
    }
}