package main

import (
	"fmt"
	"path/filepath"
)

func main() {
	fmt.Println("Blacklist(\"whatever.exe\"):", Blacklist("whatever.exe"))
}

// Blacklist returns true if a file is one of the banned types by checking its extension.
func Blacklist(filename string) bool {
	// Developers did not expect the dot to be part of the output
	if filepath.Ext(filename) == "exe" {
		return false
	}
	return true
}
