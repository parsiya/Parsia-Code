package main

import (
	"os"

	"github.com/awalterschulze/gographviz"
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

	g := gographviz.NewGraph()
	g.SetName("AST")
	g.SetDir(true)

	parse.Viz(g, "AST", "", rootNode)

	fi, err := os.Create("graph.dot")
	if err != nil {
		panic(err)
	}

	defer fi.Close()
	fi.WriteString(g.String())
}
