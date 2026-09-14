package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

func runExampleBasic() error {
	sep := strings.Repeat("=", 60)
	fmt.Println(sep)
	fmt.Println("libzupt - Basic Encryption/Decryption Example")
	fmt.Println(sep)
	fmt.Println()

	fmt.Println("1. Generating key pair...")
	keygen := NewKeyGenerator()
	keypair, err := keygen.GenerateKeyPair()
	if err != nil {
		return err
	}
	fmt.Printf("   Public key size: %d bytes\n", len(keypair.PublicKey))
	fmt.Printf("   Secret key size: %d bytes\n", len(keypair.SecretKey))
	fmt.Println()

	encryptor, err := NewEncryptor(keypair.PublicKey)
	if err != nil {
		return err
	}
	decryptor, err := NewDecryptor(keypair.SecretKey)
	if err != nil {
		return err
	}

	message := []byte("Hello, Post-Quantum World! This is a secret message.")
	fmt.Printf("2. Encrypting message: %s\n", message)
	ciphertext, encHeader, err := encryptor.Encrypt(message)
	if err != nil {
		return err
	}
	fmt.Printf("   Ciphertext size: %d bytes\n", len(ciphertext))
	fmt.Printf("   Header size: %d bytes\n", len(encHeader))
	fmt.Println()

	fmt.Println("3. Decrypting...")
	decrypted, err := decryptor.Decrypt(ciphertext, encHeader)
	if err != nil {
		return err
	}
	fmt.Printf("   Decrypted: %s\n", decrypted)
	fmt.Println()

	if !bytes.Equal(decrypted, message) {
		return errors.New("Decryption failed!")
	}
	fmt.Println("4. Verification: SUCCESS - Decrypted message matches original")
	fmt.Println()

	fmt.Println("5. Testing with wrong key...")
	keygen2 := NewKeyGenerator()
	keypair2, err := keygen2.GenerateKeyPair()
	if err != nil {
		return err
	}
	decryptorWrong, err := NewDecryptor(keypair2.SecretKey)
	if err != nil {
		return err
	}

	if _, err := decryptorWrong.Decrypt(ciphertext, encHeader); err != nil {
		fmt.Printf("   Correctly rejected with error: %v\n", err)
	} else {
		fmt.Println("   ERROR: Should have failed!")
	}
	fmt.Println()

	fmt.Println(sep)
	fmt.Println("All examples passed!")
	fmt.Println(sep)
	return nil
}
