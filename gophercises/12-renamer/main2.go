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
	err := filepath.Walk("sample", walkWithMe2(&f))
	if err != nil {
		log.Println(err)
	}

	for _, v := range f {
		fmt.Println(v)
	}
}

// walkWithMe2 stores the list of files but no directories in a slice.
func walkWithMe2(f *[]string) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		// Return error if we got an error.
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		*f = append(*f, path)
		fmt.Printf("%+v\n", info.Sys())
		return nil
	}
}
