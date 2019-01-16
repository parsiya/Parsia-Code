package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

func main() {

	memoryBlob := "3cf903522e1a3966805b50e7f7dd51dc7969c73cfb1663a75a56ebf4aa4a1849d1949005437dc44b8464dca05680d531b7a971672d87b24b7a6d672d1d811e6c34f42b2f8d7f2b43aab698b537d2df2f401c2a09fbe24c5833d2c5861139c4b4d3147abb55e671d0cac709d1cfe86860b6417bf019789950d0bf8d83218a56e69309a2bb17dcede7abfffd065ee0491b379be44029ca4321e60407d44e6e381691dae5e551cb2354727ac257d977722188a946c75a295e714b668109d75c00100b94861678ea16f8b79b756e45776d29268af1720bc49995217d814ffd1e4b6edce9ee57976f9ab398f9a8479cf911d7d47681a77152563906a2c29c6d12f971"
	encryptedAESKey, _ := hex.DecodeString(memoryBlob)

	// Read key.
	keyBytes, err := ReadFile("server-ascii.key")
	if err != nil {
		panic(err)
	}

	// Decode key.
	block, _ := pem.Decode(keyBytes)
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	// Cast to RSA private key.
	privKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		fmt.Println("bad private key")
	}
	hash := sha1.New()
	random := rand.Reader
	decryptedKey, err := rsa.DecryptOAEP(hash, random, privKey, encryptedAESKey, nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("Decrypted key:", hex.EncodeToString(decryptedKey))

	// Now read the password vault.
	vault, err := ReadFile("alabaster_passwords.elfdb.wannacookie")
	if err != nil {
		panic(err)
	}

	// Read the first four bytes to get the IV length. We know it's 16 because
	// we are using AES. But we will read it anyways.
	ivLengthBytes := vault[:4]
	// Convert it to a number.
	ivLength := uint32Little(ivLengthBytes)
	iv := vault[4 : 4+ivLength]

	fmt.Println("IV", hex.EncodeToString(iv))
	ciphertext := vault[4+ivLength:]

	cip, err := aes.NewCipher(decryptedKey)
	if err != nil {
		panic(err)
	}

	// mode := cipher.NewCFBDecrypter(cip, iv)
	mode := cipher.NewCBCDecrypter(cip, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Write to file.
	if err := WriteFile("decryptedvault", plaintext); err != nil {
		panic(err)
	}

	fmt.Println("Done - open decryptedvault")
}

// ReadFile reads all bytes in a file and returns them.
func ReadFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ioutil.ReadAll(f)
}

// WriteFile writes the data to a file.
func WriteFile(filename string, data []byte) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	n, err := f.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return fmt.Errorf("did not write all bytes. wrote %d, wanted %d", n, len(data))
	}

	return nil
}

// Borrowed from my own code at https://github.com/parsiya/golnk/blob/master/bytes.go#L180.
// uint32Little reads a uint32 from []byte and returns the result in Little-Endian.
func uint32Little(b []byte) uint32 {
	if len(b) < 4 {
		panic(fmt.Sprintf("input smaller than two bytes - got %d", len(b)))
	}
	// Length is always positive so it does not matter in this case.
	return binary.LittleEndian.Uint32(b)
}
