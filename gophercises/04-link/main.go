package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/parsiya/Parsia-Code/gophercises/04-link/link"
)

var fileName string

func init() {
	flag.StringVar(&fileName, "f", "", "HTML file")
	flag.Parse()
}

func main() {
	f, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}

	res, err := link.Parse(f)
	if err != nil {
		panic(err)
	}

	for _, v := range res {
		fmt.Println(v)
	}

}
