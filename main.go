package main

import (
	"fmt"

	"github.com/Turner-Kendall/tkgcrypt/decrypt"
	"github.com/Turner-Kendall/tkgcrypt/encrypt"
)

func main() {
	// key := "SneakyNinjasHideInPlainSight2024"
	key := "AllYourDataAreBelongToAES256Bits" // 32-byte key for AES-256

	// Encrypt the file
	if err := encrypt.EncryptFile("plaintext.txt", "encrypted.bin", key); err != nil {
		fmt.Printf("Error encrypting file: %v\n", err)
		return
	}
	fmt.Println("File encrypted successfully!")

	// Decrypt the file
	if err := decrypt.DecryptFile("encrypted.bin", "decrypted.txt", key); err != nil {
		fmt.Printf("Error decrypting file: %v\n", err)
		return
	}
	fmt.Println("File decrypted successfully!")
}
