package parse

import (
	"strings"

	blackfriday "gopkg.in/russross/blackfriday.v2"
)

// RichText returns a string with the formatted rich text section.
func RichText(input string) string {
	// Richtext content can be passed to markdown safely.
	md := string(blackfriday.Run([]byte(input), blackfriday.WithNoExtensions()))
	// Remove <p> and </p>.
	removePTags := strings.NewReplacer("<p>", "", "</p>", "")
	out := removePTags.Replace(md)
	// Trim whitespace.
	return strings.TrimSpace(out)
}
