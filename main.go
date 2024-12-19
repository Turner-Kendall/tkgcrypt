package main

import (
	"fmt"
	"os"

	"github.com/Turner-Kendall/tkgcrypt/decrypt"
	"github.com/Turner-Kendall/tkgcrypt/encrypt"
	"github.com/Turner-Kendall/tkgcrypt/utils"
)

func main() {

	key := utils.KeyPhrase()

	inFile := "plaintext.txt"
	outFile := "encrypted.bin"
	mode := "none"

	if len(os.Args) > 1 {
		mode = os.Args[1]
		inFile = os.Args[2] + ".txt"
		outFile = os.Args[2] + ".bin"
	} else {
		mode = "encrypt"
	}

	if utils.KeyLen(key) {
		fmt.Println("Valid key length!")
	} else {
		fmt.Printf("key length must be 32 bytes, got %d", len(key))
		os.Exit(1)
	}

	if mode == "encrypt" {
		if err := encrypt.EncryptFile(inFile, outFile, key); err != nil {
			fmt.Printf("Error encrypting file: %v\n", err)
			return
		}
		fmt.Println("File encrypted successfully!")
	} else if mode == "decrypt" {
		// Decrypt the file
		if err := decrypt.DecryptFile(outFile, inFile, key); err != nil {
			fmt.Printf("Error decrypting file: %v\n", err)
			return
		}
		fmt.Println("File decrypted successfully!")
	} else {
		fmt.Println("That does not compute")
		os.Exit(1)
	}

}
