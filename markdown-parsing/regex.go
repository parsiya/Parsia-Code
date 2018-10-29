package main

import (
	"fmt"
	"regexp"
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
	reStr := "(?m)^\\s*#{1}\\s*([^#\\n]+)$"
	re := regexp.MustCompile(reStr)
	result := re.FindAllStringSubmatch(testData, -1)

	fmt.Println(len(result))

	for _, match := range result {
		fmt.Println(match)
	}
}
