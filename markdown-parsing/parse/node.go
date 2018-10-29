package parse

import (
	"fmt"
	"strings"

	blackfriday "gopkg.in/russross/blackfriday.v2"
)

// PrintNode returns a string representation of the node.
func PrintNode(n *blackfriday.Node) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Type: %v - ", n.Type))
	sb.WriteString(fmt.Sprintf("Title: %v - ", n.Title))
	sb.WriteString(fmt.Sprintf("Parent: %v - ", n.Parent))
	sb.WriteString(fmt.Sprintf("Literal: %v", string(n.Literal)))
	sb.WriteString("\n--------------------")
	return sb.String()
}
