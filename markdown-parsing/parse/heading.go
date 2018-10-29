package parse

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/russross/blackfriday.v2"
)

// RawHeading represents a heading, raw content, and subheadings (if any).
type RawHeading struct {
	Title   string
	Content string
}

// Heading reads a markdown string and returns a slice of RawHeadings.
func Heading(content string, level int) (fi []RawHeading, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic in parse.Heading %v", r)
		}
	}()

	if level < 1 {
		level = 1
	}
	// Split into different sections.
	// TODO: Find better regex.
	// Narrator voice: This never happened.
	reStr := fmt.Sprintf("(?m)^\\s*#{%d}\\s*([^#\\n]+)$", level)
	re := regexp.MustCompile(reStr)
	result := re.FindAllStringSubmatchIndex(content, -1)

	/*
	   Returns slices of four ints.
	   First two are the complete heading, including the #.
	   Last two are only the heading name.
	   The rest of the heading will be from the last number of one to start of the next.
	   I will forget how this works, but it works. Don't touch it future Parsia.
	*/
	for i := range result {
		var raw RawHeading
		section := result[i]
		headingTextStart := section[2]
		headingTextEnd := section[3]

		raw.Title = content[headingTextStart:headingTextEnd]

		var startOfNextHeading int
		// Check for last item, last item continues to the end.
		if i == len(result)-1 {
			startOfNextHeading = len(content) - 1
		} else {
			startOfNextHeading = result[i+1][0]
		}
		// Trim whitespace from start and ending of content.
		raw.Content = strings.TrimSpace(content[section[3]:startOfNextHeading])
		fi = append(fi, raw)
	}
	return fi, nil
}

// IsHeading returns true if node is type heading.
func IsHeading(n *blackfriday.Node) bool {
	return n.Type == blackfriday.Heading
}

// HeadingTitle returns the title of the heading by returning the Literal of its
// first child.
func HeadingTitle(n *blackfriday.Node) string {
	// Check if it has a child and its of type Text. Headings might not have titles.
	if n.FirstChild != nil && n.FirstChild.Type == blackfriday.Text {
		return string(n.FirstChild.Literal)
	}
	// This is not exactly idiomatic because successful return value should be
	// the last return. However, this looks clearer.
	return ""
}

// PrintHeading returns the information of a Heading node.
func PrintHeading(n *blackfriday.Node) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Heading Title: %s - ", HeadingTitle(n)))
	sb.WriteString(fmt.Sprintf("Heading Level: %d - ", n.HeadingData.Level))
	sb.WriteString(fmt.Sprintf("Heading HeadingID: %s - ", n.HeadingData.HeadingID))
	sb.WriteString(fmt.Sprintf("Heading IsTitleBlock: %v", n.HeadingData.IsTitleblock))
	sb.WriteString("\n")
	sb.WriteString(PrintNode(n))

	return sb.String()
}
