package main

import (
	"flag"
	"fmt"
	"strings"
)

var input string

func init() {
	flag.StringVar(&input, "i", "saveChangesInTheEditor", "camelCase string")
	flag.Parse()
}

func main() {
	fmt.Printf("Number of words in %v: %d\n", input, camelcase(input))
}

// camelcase returns the number of words in the input.
func camelcase(s string) int {

	// If we were only looking at ASCII-Hex characters, then we could just
	// compare the ASCII codes. Anything between 0x41 ("A") and 0x5A ("Z")
	// inclusive is capital.
	// A better way is to use the strings.ToUpper method and compare it with
	// the actual string.

	count := 0
	for _, char := range s {
		// Remember char is a rune, so it must be converted to string.
		ch := string(char)
		if strings.ToUpper(ch) == ch {
			count++
		}
	}
	return count + 1
}
