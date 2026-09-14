package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func runExampleFile() error {
	sep := strings.Repeat("=", 60)
	fmt.Println(sep)
	fmt.Println("libzupt - File Encryption/Decryption Example")
	fmt.Println(sep)
	fmt.Println()

	fmt.Println("1. Generating key pair...")
	keygen := NewKeyGenerator()
	keypair, err := keygen.GenerateKeyPair()
	if err != nil {
		return err
	}
	fmt.Println("   Key pair generated")
	fmt.Println()

	encryptor, err := NewEncryptor(keypair.PublicKey)
	if err != nil {
		return err
	}
	decryptor, err := NewDecryptor(keypair.SecretKey)
	if err != nil {
		return err
	}

	tmpDir, err := os.MkdirTemp("", "zupt_example_")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	testFile := filepath.Join(tmpDir, "example.txt")
	content := "This is a secret text file.\n" +
		"Line 2: Contains sensitive information.\n" +
		"Line 3: End of file.\n"
	original := []byte(content)
	if err := os.WriteFile(testFile, original, 0o600); err != nil {
		return err
	}

	fmt.Printf("2. Created test file: %s\n", testFile)
	fmt.Printf("   Original content:\n%s", original)
	fmt.Println()

	fmt.Println("3. Encrypting file...")
	ciphertext, encHeader, err := encryptor.EncryptFile(testFile)
	if err != nil {
		return err
	}
	fmt.Printf("   Ciphertext size: %d bytes\n", len(ciphertext))
	fmt.Printf("   Header size: %d bytes\n", len(encHeader))
	fmt.Println()

	cipherFile := testFile + ".enc"
	if err := os.WriteFile(cipherFile, ciphertext, 0o600); err != nil {
		return err
	}
	fmt.Printf("4. Saved ciphertext to: %s\n", cipherFile)
	fmt.Println()

	fmt.Println("5. Decrypting file...")
	decrypted, err := decryptor.DecryptFile(cipherFile, encHeader)
	if err != nil {
		return err
	}
	fmt.Printf("   Decrypted size: %d bytes\n", len(decrypted))
	fmt.Printf("   Decrypted content:\n%s", decrypted)
	fmt.Println()

	if !bytes.Equal(decrypted, original) {
		return errors.New("Decryption failed!")
	}

	fmt.Println("6. Cleaned up temporary files")
	fmt.Println()

	fmt.Println(sep)
	fmt.Println("File encryption/decryption example passed!")
	fmt.Println(sep)
	return nil
}
