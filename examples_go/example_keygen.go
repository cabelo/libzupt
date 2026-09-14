package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func runExampleKeygen() error {
	sep := strings.Repeat("=", 60)
	fmt.Println(sep)
	fmt.Println("libzupt - Key Generation and Management Example")
	fmt.Println(sep)
	fmt.Println()

	tmpDir, err := os.MkdirTemp("", "zupt_keygen_")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	privKeyFile := filepath.Join(tmpDir, "private.key")
	pubKeyFile := filepath.Join(tmpDir, "public.key")

	fmt.Println("1. Generating key pair...")
	keygen := NewKeyGenerator()
	keypair, err := keygen.GenerateKeyPair()
	if err != nil {
		return err
	}
	fmt.Printf("   Public key: %d bytes\n", len(keypair.PublicKey))
	fmt.Printf("   Private key: %d bytes\n", len(keypair.SecretKey))
	fmt.Println()

	fmt.Println("2. Saving key pair...")
	if err := keygen.SaveKeyPair(keypair, privKeyFile); err != nil {
		return err
	}
	fmt.Printf("   Saved to: %s\n", privKeyFile)
	fmt.Println()

	fmt.Println("3. Exporting public key...")
	if err := keygen.ExportPublicKey(privKeyFile, pubKeyFile); err != nil {
		return err
	}
	fmt.Printf("   Saved to: %s\n", pubKeyFile)
	fmt.Println()

	fmt.Println("4. Loading key pair...")
	loadedKeypair, err := keygen.LoadKeyPair(privKeyFile)
	if err != nil {
		return err
	}
	fmt.Printf("   Loaded public key: %d bytes\n", len(loadedKeypair.PublicKey))
	fmt.Printf("   Loaded private key: %d bytes\n", len(loadedKeypair.SecretKey))
	if !bytes.Equal(loadedKeypair.PublicKey, keypair.PublicKey) {
		return errors.New("Public keys do not match!")
	}
	if !bytes.Equal(loadedKeypair.SecretKey, keypair.SecretKey) {
		return errors.New("Secret keys do not match!")
	}
	fmt.Println("   Keys match!")
	fmt.Println()

	fmt.Println("5. Loading public key only...")
	loadedPub, err := keygen.LoadPublicKey(pubKeyFile)
	if err != nil {
		return err
	}
	fmt.Printf("   Loaded public key: %d bytes\n", len(loadedPub))
	if !bytes.Equal(loadedPub, keypair.PublicKey) {
		return errors.New("Public key does not match!")
	}
	fmt.Println("   Public key matches!")
	fmt.Println()

	fmt.Println("6. Key sizes (bytes):")
	fmt.Printf("   ML-KEM public key: %d\n", MLKEMPublicKeyBytes)
	fmt.Printf("   X25519 public key: %d\n", X25519KeyBytes)
	fmt.Printf("   Hybrid public key: %d\n", HybridPubKeySize)
	fmt.Printf("   Hybrid private key: %d\n", HybridPrivKeySize)
	fmt.Printf("   Encryption header: %d\n", HybridEncHeaderSize)
	fmt.Println()

	fmt.Println(sep)
	fmt.Println("Key management example passed!")
	fmt.Println(sep)
	return nil
}
