package main

import (
	"fmt"
	"os"
	"strings"
)

type example struct {
	name  string
	title string
	run   func() error
}

func main() {
	examples := []example{
		{"basic", "Basic Encryption/Decryption", runExampleBasic},
		{"file", "File Encryption/Decryption", runExampleFile},
		{"keygen", "Key Generation and Management", runExampleKeygen},
		{"random", "Random Bytes and Hashing", runExampleRandom},
		{"secure_buffer", "SecureBuffer", runExampleSecureBuffer},
	}

	var selection string
	if len(os.Args) > 1 {
		selection = strings.ToLower(os.Args[1])
	}

	var toRun []example
	switch selection {
	case "", "all", "--all":
		toRun = examples
	case "-h", "--help", "help":
		fmt.Println("Usage: zupt_example [example]")
		fmt.Println()
		fmt.Println("Available examples:")
		for _, e := range examples {
			fmt.Printf("  %-14s %s\n", e.name, e.title)
		}
		fmt.Println("  all            Run every example (default)")
		return
	default:
		found := false
		for _, e := range examples {
			if e.name == selection {
				toRun = []example{e}
				found = true
				break
			}
		}
		if !found {
			fmt.Fprintf(os.Stderr, "ERROR: unknown example: '%s'\n", selection)
			os.Exit(1)
		}
	}

	for _, e := range toRun {
		if err := e.run(); err != nil {
			fmt.Fprintln(os.Stderr)
			fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
			os.Exit(1)
		}
	}
}
