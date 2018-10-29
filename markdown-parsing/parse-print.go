package main

import (
	"fmt"

	"github.com/parsiya/Parsia-Code/markdown-parsing/parse"

	blackfriday "gopkg.in/russross/blackfriday.v2"
)

var testData = `
# Heading 1

## Heading 1-1
Content of heading 1-1.

More lines in heading 1-1.

## Heading 1-2
Content of heading 1-1.

More lines in heading 1-1.

## Heading 1-3
* https://example.net
    * email: someemail@example.net
    * address: 123 street name
* https://google.com
    * email: blahblah
* https://parsiya.net
* http://parsiya.io

# Heading 2

## Heading 2-1
Heading 2-1 content.
`

func main() {
	md := blackfriday.New(blackfriday.WithNoExtensions())
	rootNode := md.Parse([]byte(testData))
	// rootNode is always of NodeType "Document" or 0.
	rootNode.Walk(func(node *blackfriday.Node, entering bool) blackfriday.WalkStatus {
		fmt.Println(parse.PrintNode(node))
		return blackfriday.GoToNext
	})
}
