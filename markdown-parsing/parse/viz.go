package parse

import (
	"strconv"
	"strings"

	"github.com/awalterschulze/gographviz"
	blackfriday "gopkg.in/russross/blackfriday.v2"
)

var counter = 0

// Viz adds a node to the graph and adds an edge to its parent.
func Viz(graph *gographviz.Graph, graphName, parentID string, node *blackfriday.Node) {

	myID := strconv.Itoa(counter)
	attrs := make(map[string]string)
	attrs[string(gographviz.Label)] = Label(node)
	graph.AddNode(graphName, myID, attrs)

	// If not root, add an edge to parent.
	// TODO: How can we eliminate this check to speed things up?
	if parentID != "" {
		graph.AddEdge(parentID, myID, true, nil)
	}

	// Increase counter.
	counter++

	child := node.FirstChild
	for child != nil {
		Viz(graph, graphName, myID, child)
		child = child.Next
	}
}

// Label returns a label for the node. Label is "Node.Type\n\Node.String()".
func Label(node *blackfriday.Node) string {
	var sb strings.Builder
	// We might need to add a new line to label, so we need to enclose the
	// label in double-quotes.
	sb.WriteString("\"")
	sb.WriteString(node.Type.String())
	if len(node.Literal) != 0 {
		sb.WriteString("\\n" + node.String())
	}
	sb.WriteString("\"")
	return sb.String()
}
