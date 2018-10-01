package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/parsiya/Parsia-Code/gophercises/17-secret/keystore"
)

func main() {

	ks := &keystore.KeyStore{}
	var err error

	os.Remove("test.enc")

	ks, err = keystore.MakeKeyStore("Hello", "test.enc")
	if err != nil && strings.Contains(err.Error(), "exists") {
		ks, err = keystore.GetKeyStore("Hello", "test.enc")
	}
	if err != nil {
		panic(err)
	}

	fmt.Println(ks)

	ci, err := ks.Encrypt("HelloHelloHelloHelloHelloHelloHelloHello")
	if err != nil {
		panic(err)
	}
	fmt.Printf("%x\n", ci)
	fmt.Println(len(ci))

	pl, err := ks.Decrypt(ci)
	if err != nil {
		panic(err)
	}
	fmt.Println(pl)

	// Set something.

	ks.Set("key1", "val1111111111111111111")
	ks.Set("key2", "val2")
	fmt.Println(ks.Get("key1"))
	fmt.Println(ks.Get("key2"))
	ks.SaveKeyStore()
	fmt.Println(ks.Get("key3"))
	ks.Set("key3", "val3")
	ks.Set("key4", "val4")
	ks.SaveKeyStore()

	k2, err := keystore.GetKeyStore("Hello", "test.enc")
	if err != nil {
		panic(err)
	}
	fmt.Println(k2)
	fmt.Println(k2.Get("key1"))

	fmt.Println(ks.Get("key1"))
}
