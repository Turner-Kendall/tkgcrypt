package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
)

// EncryptFile encrypts the contents of an input file and writes the encrypted data to an output file using AES-GCM.
func EncryptFile(inputFile, outputFile, key string) error {
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	plaintext, err := io.ReadAll(inFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	if _, err = outFile.Write(ciphertext); err != nil {
		return fmt.Errorf("failed to write to output file: %w", err)
	}

	return nil
}
