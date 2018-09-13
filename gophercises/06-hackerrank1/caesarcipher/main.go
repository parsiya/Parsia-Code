package main

import (
	"flag"
	"fmt"
)

// Input is in format of
// length 	 int
// plaintext string
// key		 int
var length int
var plaintext string
var key int

func init() {
	flag.IntVar(&length, "len", 0, "length of plaintext")
	flag.StringVar(&plaintext, "plaintext", "", "plaintext")
	flag.IntVar(&key, "key", 0, "key - a.k.a. how many positions to shift")
	flag.Parse()
}

func main() {

	if plaintext == "" {
		fmt.Println("Input was empty.")
		return
	}

	if len(plaintext) != length {
		fmt.Println("length and input do not match.")
		fmt.Printf("length: %d - length of input: %d\n", length, len(plaintext))
		return
	}

	// No need to do a lot of rotates.
	key = key % 26

	var ciphertext []rune

	for _, r := range plaintext {
		ciphertext = append(ciphertext, Encrypt(r, key))
	}

	fmt.Println(string(ciphertext))

}

// ROR shifts the current character to right and rotates.
// Capital letter and small letters are managed independently.
func ROR(r rune, start rune, shift int) rune {
	// First convert run to int (to get the ASCII code).
	asc := int(r)
	// Next get the relative location compared to base.
	asc = asc - int(start)
	// Next we will move by shift and mod 26.
	asc = (asc + shift) % 26
	// Finally add by base to get the new item.
	asc = asc + int(start)
	// Return as rune.
	return rune(asc)
}

// Encrypt detects the start and encrypts the appropriate characters.
func Encrypt(r rune, key int) rune {
	if 'Z' >= r && r >= 'A' {
		return ROR(r, 'A', key)
	}

	if 'z' > r && r > 'a' {
		return ROR(r, 'a', key)
	}

	return r
}
