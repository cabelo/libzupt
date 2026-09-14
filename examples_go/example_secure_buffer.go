package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

func runExampleSecureBuffer() error {
	sep := strings.Repeat("=", 60)
	fmt.Println(sep)
	fmt.Println("libzupt - SecureBuffer Example")
	fmt.Println(sep)
	fmt.Println()

	fmt.Println("1. Creating SecureBuffer from bytes...")
	secret := []byte("My secret password123")
	buffer := NewSecureBuffer(secret)
	fmt.Printf("   Buffer size: %d bytes\n", buffer.Size())
	fmt.Printf("   Buffer content: %s\n", buffer.String())
	fmt.Println()

	fmt.Println("2. Creating empty SecureBuffer...")
	emptyBuffer := NewSecureBufferSize(64)
	fmt.Printf("   Empty buffer size: %d bytes\n", emptyBuffer.Size())
	fmt.Println()

	fmt.Println("3. Encrypting with SecureBuffer...")
	keygen := NewKeyGenerator()
	keypair, err := keygen.GenerateKeyPair()
	if err != nil {
		return err
	}
	encryptor, err := NewEncryptor(keypair.PublicKey)
	if err != nil {
		return err
	}
	decryptor, err := NewDecryptor(keypair.SecretKey)
	if err != nil {
		return err
	}

	ciphertext, encHeader, err := encryptor.EncryptSecure(buffer)
	if err != nil {
		return err
	}
	fmt.Printf("   Ciphertext size: %d bytes\n", len(ciphertext))
	fmt.Println()

	fmt.Println("4. Decrypting to SecureBuffer...")
	decryptedBuffer, err := decryptor.DecryptSecure(ciphertext, encHeader)
	if err != nil {
		return err
	}
	fmt.Printf("   Decrypted buffer size: %d bytes\n", decryptedBuffer.Size())
	fmt.Printf("   Decrypted content: %s\n", decryptedBuffer.String())
	fmt.Println()

	if !bytes.Equal(decryptedBuffer.ToBytes(), secret) {
		return errors.New("Decryption failed!")
	}
	fmt.Println("5. Verification: SUCCESS")
	fmt.Println()

	fmt.Println("6. Securely wiping buffer...")
	buffer.Zeroize()
	fmt.Println("   Buffer zeroized (content is now zero)")
	fmt.Println()

	fmt.Println(sep)
	fmt.Println("SecureBuffer example passed!")
	fmt.Println(sep)
	return nil
}
