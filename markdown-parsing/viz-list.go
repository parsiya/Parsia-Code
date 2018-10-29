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

	g := gographviz.NewGraph()
	g.SetName("list")
	g.SetDir(true)

	rootNode.Walk(func(node *blackfriday.Node, entering bool) blackfriday.WalkStatus {
		// Check if node has a parent, otherwise we will panic when we check
		// the panret type.
		if node.Parent != nil {
			if node.Type == blackfriday.List && node.Parent.Type == blackfriday.Document {
				parse.Viz(g, "list", "", node)
				return blackfriday.Terminate
			}
		}
		return blackfriday.GoToNext
	})

	fi, err := os.Create("graph-list.dot")
	if err != nil {
		panic(err)
	}
	defer fi.Close()
	fi.WriteString(g.String())
}
