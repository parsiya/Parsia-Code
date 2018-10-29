package main

import (
	"fmt"

	"github.com/parsiya/Parsia-Code/markdown-parsing/parse"
)

var testData = `
# Heading 1

## Heading 1-1
Content of heading 1-1.

More lines in heading 1-1.

## Heading 1-2
Content of heading 1-2.

More lines in heading 1-2.

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
	levelOnes, err := parse.Heading(testData, 1)
	if err != nil {
		panic(err)
	}
	for _, l1 := range levelOnes {
		fmt.Println("Level 1 title:", l1.Title)
		levelTwos, _ := parse.Heading(l1.Content, 2)
		for _, l2 := range levelTwos {
			fmt.Println("Level 2 title:", l2.Title)
			fmt.Println("Level 2 content:", l2.Content)
			fmt.Println("********************")
		}
		fmt.Println("--------------------")
	}
}
