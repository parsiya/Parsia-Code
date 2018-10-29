package main

import (
	"fmt"

	"github.com/parsiya/Parsia-Code/markdown-parsing/parse"
)

var someRichText = `
This is line one.

This is line two.

This is a list:

* item1
* item2
`

func main() {
	fmt.Println(parse.RichText(someRichText))
}
