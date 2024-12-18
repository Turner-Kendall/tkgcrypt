// decrypt_test.go

package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"os"
	"testing"

	"github.com/Turner-Kendall/tkgcrypt/utils"
)

func encryptFile(inputFile, key string) error {

	if utils.KeyLen(key) {
		fmt.Println("Valid key length!")
	} else {
		return fmt.Errorf("key length must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	plaintext := []byte("This is the plaintext that we are encrypting.")

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return os.WriteFile(inputFile, ciphertext, 0644)
}

func TestDecryptFile(t *testing.T) {
	input := "test.enc"
	output := "test.dec"
	key := "AllYourDataAreBelongToAES256Bits"

	// Encrypt a file first (to simulate real encryption)
	err := encryptFile(input, key)
	if err != nil {
		t.Fatalf("Failed to create test encrypted file: %v", err)
	}

	defer os.Remove(input)
	defer os.Remove(output)

	// Decrypt the file
	err = DecryptFile(input, output, key)
	if err != nil {
		t.Fatalf("DecryptFile failed: %v", err)
	}

	// Verify the output file exists
	if _, err := os.Stat(output); os.IsNotExist(err) {
		t.Fatalf("Output file was not created")
	}

	// Verify contents of the output file
	expected := "This is the plaintext that we are encrypting."
	decryptedData, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decryptedData) != expected {
		t.Fatalf("Decrypted content mismatch. Got: %s, Expected: %s", string(decryptedData), expected)
	}
}
