package main

import (
	"encoding/hex"
	"fmt"
	"strings"
)

func runExampleRandom() error {
	sep := strings.Repeat("=", 60)
	fmt.Println(sep)
	fmt.Println("libzupt - Random Bytes and Hashing Example")
	fmt.Println(sep)
	fmt.Println()

	fmt.Println("1. Generating random bytes...")
	randomBytes := RandomBytes(32)
	fmt.Printf("   Generated %d random bytes:\n", len(randomBytes))
	fmt.Printf("   %s\n", hex.EncodeToString(randomBytes))
	fmt.Println()

	fmt.Println("2. Generating AES nonce...")
	nonce := RandomBytes(AESNonceSize)
	fmt.Printf("   Nonce (%d bytes): %s\n", len(nonce), hex.EncodeToString(nonce))
	fmt.Println()

	fmt.Println("3. Computing SHA-256 hash...")
	data := []byte("Hello, Post-Quantum World!")
	sha256Hash := Sha256(data)
	fmt.Printf("   Data: %s\n", data)
	fmt.Printf("   SHA-256: %s\n", hex.EncodeToString(sha256Hash))
	fmt.Println()

	fmt.Println("4. Computing SHA3-512 hash...")
	sha3_512Hash := Sha3_512(data)
	fmt.Printf("   Data: %s\n", data)
	fmt.Printf("   SHA3-512: %s\n", hex.EncodeToString(sha3_512Hash))
	fmt.Println()

	fmt.Println("5. Simulating key derivation...")
	salt := RandomBytes(16)
	fmt.Printf("   Salt: %s\n", hex.EncodeToString(salt))
	derivedInput := make([]byte, 0, len(salt)+len("my-secret-password"))
	derivedInput = append(derivedInput, salt...)
	derivedInput = append(derivedInput, []byte("my-secret-password")...)
	derivedKey := Sha256(derivedInput)
	fmt.Printf("   Derived key (32 bytes): %s\n", hex.EncodeToString(derivedKey))
	fmt.Println()

	fmt.Println(sep)
	fmt.Println("Random bytes and hashing example passed!")
	fmt.Println(sep)
	return nil
}
