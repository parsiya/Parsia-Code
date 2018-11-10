package main

import (
	"fmt"
	"path/filepath"
)

func main() {
	fmt.Println("Blacklist(\"whatever.exe\"):", Blacklist("whatever.exe"))
	fmt.Println("Blacklist(\"whatever.ExE\"):", Blacklist("whatever.ExE"))
}

// Blacklist returns true if a file is one of the banned types by checking its extension.
func Blacklist(filename string) bool {
	if filepath.Ext(filename) == ".exe" {
		return false
	}
	return true
}
