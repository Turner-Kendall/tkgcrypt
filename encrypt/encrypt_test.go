// encrypt_test.go

package encrypt

import (
	"fmt"
	"os"
	"testing"

	"github.com/Turner-Kendall/tkgcrypt/utils"
)

func TestEncryptFile(t *testing.T) {
	input := "test.txt"
	output := "test.enc"
	key := "AllYourDataAreBelongToAES256Bits" // 32-byte key for AES-256

	if utils.KeyLen(key) {
		fmt.Println("Valid key length!")
	} else {
		fmt.Printf("key length must be 32 bytes, got %d", len(key))
	}

	err := os.WriteFile(input, []byte("Hey, Now!"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test input file: %v", err)
	}
	defer os.Remove(input)
	// defer os.Remove(output)

	err = EncryptFile(input, output, key)
	if err != nil {
		t.Fatalf("EncryptFile failed: %v", err)
	}

	if _, err := os.Stat(output); os.IsNotExist(err) {
		t.Fatalf("Output file was not created")
	}
}
