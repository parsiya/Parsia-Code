package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func main() {

	// Make a list of all files in sample.
	err := filepath.Walk("sample", walkWithMe0)
	if err != nil {
		log.Println(err)
	}
}

// walkWithMe0 returns info about files.
func walkWithMe0(path string, info os.FileInfo, err error) error {

	// Now we can do what we want with os.FileInfo.
	fmt.Printf("Visiting %v\n", info.Name())
	return nil
}
