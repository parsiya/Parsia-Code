package link

import (
	"fmt"
	"io"
	"strings"

	"golang.org/x/net/html"
)

// Link is an href in the HTML file.
type Link struct {
	Link string
	Text string
}

// Parse parses an io.Reader containing raw HTML an extract the links.
func Parse(r io.Reader) ([]Link, error) {
	z := html.NewTokenizer(r)

	var links []Link
	capturing := false
	var sb strings.Builder
	var tempLink Link

	for {
		// Check if we have reached the end of reader (or another error).
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		tk := z.Token()

		// If capturing, capture the text of all Text tokens.
		if capturing && tk.Type == html.TextToken {
			d := strings.TrimSpace(tk.Data)
			// Add a space between these.
			_, err := sb.WriteString(" ")
			if err != nil {
				return links, err
			}
			_, err = sb.WriteString(d)
			if err != nil {
				return links, err
			}
		}

		// <a href="https://example.net">
		// Type: StartTag
		// DataAtom: a
		// Data: a
		// Attrib.Namespace:
		// Attrib.Key: href
		// Attrib.Val: https://example.net

		// If we reach <a
		if IsStartAnchor(tk) {
			// Cycle through all attributes and extract href.
			for _, v := range tk.Attr {
				if v.Key == "href" {
					tempLink.Link = v.Val
					// We got the href, no need to loop.
					break
				}
			}
			// Start capturing
			capturing = true
		}

		// If we reach </a>
		if IsEndAnchor(tk) {
			// Store the string builder.
			tempLink.Text = sb.String()
			// Add tempLink to links if it's not empty
			if tempLink.Link != "" && tempLink.Text != "" {
				links = append(links, tempLink)
			}
			// End capturing.
			capturing = false
			// Reset the string builder.
			sb.Reset()
			// Reset tempLink
			tempLink.Link = ""
			tempLink.Text = ""
		}
	}

	return links, nil
}

// Stringer for Link struct.
func (l Link) String() string {
	return fmt.Sprintf("Link: %s - Text: %s", l.Link, l.Text)
}

// IsStartAnchor returns true if an html.Token is a starting href.
// <a href="example.net">
func IsStartAnchor(tk html.Token) bool {
	return tk.Type == html.StartTagToken && tk.Data == "a"
}

// IsEndAnchor returns true if an html.Token is a closing href.
// </a>
func IsEndAnchor(tk html.Token) bool {
	return tk.Type == html.EndTagToken && tk.Data == "a"
}
