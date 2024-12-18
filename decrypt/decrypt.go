// decrypt.go

package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"os"
)

// DecryptFile decrypts an encrypted file using AES-GCM and writes the plaintext to an output file.
func DecryptFile(inputFile, outputFile, key string) error {
	// Ensure the key is valid for AES (16, 24, 32 bytes)
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return fmt.Errorf("invalid key length: expected 16, 24, or 32 bytes, got %d", len(key))
	}

	// Open the input encrypted file
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inFile.Close()

	// Read all bytes from the input file (ciphertext + nonce)
	ciphertext, err := io.ReadAll(inFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Create the AES cipher block
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Extract the nonce from the ciphertext
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return fmt.Errorf("ciphertext too short: expected at least %d bytes, got %d", nonceSize, len(ciphertext))
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the ciphertext
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt file: %w", err)
	}

	// Write the plaintext to the output file
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	if _, err = outFile.Write(plaintext); err != nil {
		return fmt.Errorf("failed to write to output file: %w", err)
	}

	return nil
}
