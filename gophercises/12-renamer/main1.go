package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func main() {

	var f []string
	// Make a list of all files in sample.
	err := filepath.Walk("sample", walkWithMe1(&f))
	if err != nil {
		log.Println(err)
	}

	for _, v := range f {
		fmt.Println(v)
	}
}

// walkWithMe1 stores the list of files in a slice.
func walkWithMe1(f *[]string) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		// Return error if we got an error.
		if err != nil {
			return err
		}
		*f = append(*f, path)
		return nil
	}
}
