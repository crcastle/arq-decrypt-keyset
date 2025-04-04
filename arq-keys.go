package main

/**
* 
* This implements the password verification algorithm described at
* https://www.arqbackup.com/docs/arqcloudbackup/English.lproj/dataFormat.html
* in the section named "/encrypted_master_keys.dat". Specifically, it implements
* steps 1 and 2 to determine if the password is correct or the .dat file is
* corrupted (or both).
*
*/

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

func deriveKey(password, salt []byte, iterations, keyLen int) []byte {
	return pbkdf2.Key(password, salt, iterations, keyLen, sha1.New)
}

func calculateHMACSHA256(message []byte, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return h.Sum(nil)
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: arq-keys <path-to-encrypted_master_keys.dat> <password>")
		os.Exit(1)
	}

	path := os.Args[1]
	password := []byte(os.Args[2])

	fileBytes, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}

	byteCountLabel := " (%d bytes)\n"

	fmt.Printf("File bytes:\t\t %x", fileBytes)
	fmt.Printf(byteCountLabel, len(fileBytes))

	fmt.Println("------------")
	fmt.Println("File parts according to docs:")

	header := fileBytes[:25]
	fmt.Printf("Header:\t\t\t %x (or %s in UTF-8)", header, header)
	fmt.Printf(byteCountLabel, len(header))

	salt := fileBytes[25:33]
	fmt.Printf("Salt:\t\t\t %x", salt)
	fmt.Printf(byteCountLabel, len(salt))

	hmacSha256 := fileBytes[33:65]
	fmt.Printf("HMAC:\t\t\t %x", hmacSha256)
	fmt.Printf(byteCountLabel, len(hmacSha256))

	iv := fileBytes[65:81]
	fmt.Printf("IV:\t\t\t %x", iv)
	fmt.Printf(byteCountLabel, len(iv))

	encryptedKeySet := fileBytes[81:]
	fmt.Printf("Encrypted key set:\t %x", encryptedKeySet)
	fmt.Printf(byteCountLabel, len(encryptedKeySet))

	fmt.Println("------------")

	iterations := 200_000
	keyLen := 64

	derivedKey := deriveKey(password, salt, iterations, keyLen)
	fmt.Printf("Derived key:\t\t %x", derivedKey)
	fmt.Printf(byteCountLabel, len(derivedKey))

	ivAndEncryptedKeySet := append(iv, encryptedKeySet...)
	fmt.Printf("IV & encrypted key set:\t %x", ivAndEncryptedKeySet)
	fmt.Printf(byteCountLabel, len(ivAndEncryptedKeySet))

	last128Bytes := fileBytes[len(fileBytes)-128:]
	fmt.Printf("Last 128 bytes of file:\t %x", last128Bytes)
	fmt.Printf(byteCountLabel, len(last128Bytes))

	calculatedHmacSha256IvEnc := calculateHMACSHA256(ivAndEncryptedKeySet, derivedKey[32:])
	calculatedHmacSha256Last128 := calculateHMACSHA256(last128Bytes, derivedKey[32:])

	fmt.Println()
	fmt.Println("**One of the below two values should match the HMAC above**")
	fmt.Println("(unclear which should match because the file .dat is 209 bytes instead of the expected 193 bytes)")
	fmt.Println()
	fmt.Printf("Calculated HMAC of IV & enc key set:\t\t %x\n", calculatedHmacSha256IvEnc)
	fmt.Printf("Calculated HMAC of last 128 bytes of file:\t %x\n", calculatedHmacSha256Last128)
	fmt.Println()
	if !hmac.Equal(hmacSha256, calculatedHmacSha256IvEnc) || !hmac.Equal(hmacSha256, calculatedHmacSha256Last128) {
		fmt.Println("No match")
	} else {
		fmt.Println("*****  Match!!!!!!  *****")
	}
	fmt.Println()
	fmt.Println("If there is not a match, either the password is incorrect or the .dat file is corrupt")

}
