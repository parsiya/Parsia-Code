package main

import (
	"fmt"
	"path/filepath"
)

// Ext case tests.

func main() {
	fmt.Println("filepath.Ext(\"whatever.txt\"):", filepath.Ext("whatever.txt"))
	fmt.Println("filepath.Ext(\"whatever.TXT\"):", filepath.Ext("whatever.TXT"))
	fmt.Println("filepath.Ext(\"whatever.Txt\"):", filepath.Ext("whatever.Txt"))
}
