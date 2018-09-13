package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// urlset is used for XML encoding.
type urlset struct {
	Urls  []xmlLink `xml:"url"`
	Xmlns string    `xml:"xmlns,attr"`
}

// xmlLink is used for XML encoding.
type xmlLink struct {
	URL string `xml:"loc"`
}

// myLink represents a link with depth.
type myLink struct {
	URL   url.URL `xml:"loc"`
	Depth int
}

// String is stringer for myLink
func (m myLink) String() string {
	return fmt.Sprintf("URL: %v - Depth %v", m.URL.String(), m.Depth)
}

type mapper struct {
	MaxDepth int
	// If value is true, it means it is visited.
	Visited map[url.URL]bool
	Start   url.URL
	Q       chan myLink
}

// Init initializes the mapper with the initial uRL and max depth.
func (m *mapper) Init(initialURL string, max int) error {
	myLog.Println("Initializing mapper.")
	u, err := url.Parse(initialURL)
	if err != nil {
		return err
	}
	if max < 0 {
		return fmt.Errorf("max depth cannot be negative: %v was provided", max)
	}
	if !u.IsAbs() {
		return fmt.Errorf("starting URL must be absolute: %v was provided", initialURL)
	}
	m.Start = *u
	m.MaxDepth = max
	m.Visited = make(map[url.URL]bool)
	// This number should be high, otherwise the app will hang.
	m.Q = make(chan myLink, 10000)
	startLink := myLink{URL: m.Start, Depth: 0}
	m.Q <- startLink
	return nil
}

// InScope returns true if the URL is part of the starting domain.
func (m *mapper) InScope(u url.URL) bool {
	return strings.ToLower(m.Start.Host) == strings.ToLower(u.Host)
}

// Cleanup converts a URL to absolute form and lower case, removes trailing
// slash and fragment (e.g. #whatver).
func (m *mapper) CleanUp(u string) (url.URL, error) {
	// Make a copy of starting URL.
	st := m.Start

	// Parse the URL
	ur, err := url.Parse(u)
	if err != nil {
		return *ur, err
	}

	// Add trailing slash to empty paths.
	if ur.Path == "" {
		ur.Path = "/"
	}

	// Add trailing slash to non-empty paths.
	if ur.Path[len(ur.Path)-1:] != "/" {
		ur.Path = ur.Path + "/"
	}

	// Remove fragment.
	ur.Fragment = ""

	// If it's already absolute, convert to url.URL and return it.
	if ur.IsAbs() {
		return *ur, nil
	}

	// Modify the starting URL copy and just change the path.
	st.Path = ur.Path
	return st, nil
}

// Parse extracts all URLs from a link.
func (m *mapper) Parse(l myLink) ([]myLink, error) {
	// First check if it's in scope.
	if !m.InScope(l.URL) {
		return nil, fmt.Errorf("URL not in scope, skipping")
	}

	// Don't bother if we have reached max depth.
	if l.Depth >= m.MaxDepth {
		return nil, fmt.Errorf("Max depth reached, skipping")
	}

	resp, err := GetURL(l.URL.String())
	if err != nil {
		return nil, fmt.Errorf("error in http.GET(%v) - %v", l.URL.String(), err)
	}

	// Parse the HTML but only grab the hrefs.
	z := html.NewTokenizer(resp)

	var links []myLink

	myLog.Println("Finished tokenizing.")
	for {
		// Check if we have reached the end of reader (or another error).
		tt := z.Next()
		if tt == html.ErrorToken {
			myLog.Printf("z.Next() error: %v\n", tt)
			break
		}
		tk := z.Token()
		// myLog.Printf("Current tk: %v\n", tk.Data)
		// if tk.Data == "a" {
		// 	myLog.Println("FOUND it")
		// }

		// If we reach <a
		if IsStartAnchor(tk) {
			// myLog.Println("Found tk.Data == \"a\"")
			// Cycle through all attributes and extract href.
			for _, v := range tk.Attr {
				if v.Key == "href" {
					// myLog.Printf("Found href %v", v.Val)
					tempURL, err := m.CleanUp(v.Val)
					if err != nil {
						myLog.Printf("error parsing %v: %v\n", tempURL.String(), err)
					}

					if m.InScope(tempURL) {
						newLink := myLink{
							Depth: l.Depth + 1,
							URL:   tempURL,
						}
						myLog.Printf("Found link %v\n", newLink.URL.String())
						links = append(links, newLink)
					}
					// We got the href, no need to loop.
					break
				}
			}
		}
	}
	return links, nil
}

// Process reads items from channel, if they are not visited, it visits them.
func (m *mapper) Process() {

Mainloop:
	for {
		select {
		case l := <-m.Q:
			if _, exists := m.Visited[l.URL]; exists {
				myLog.Printf("URL already visited: %v\n", l.URL.String())
				continue
			}
			myLog.Printf("Processing %v\n", l.String())
			m.Visited[l.URL] = true
			newLinks, err := m.Parse(l)
			if err != nil {
				myLog.Printf("error in Parse: %v\n", err)
			}
			for _, li := range newLinks {
				// Only add if it's not already visited.
				if m.AlreadyVisited(li) {
					continue
				}
				myLog.Printf("adding link %v\n", li.URL.String())
				m.Q <- li
			}
			myLog.Printf("Finished processing %v\n", l.String())
		default:
			// myLog.Println("in default")
			break Mainloop
		}

	}
	myLog.Printf("End of for")
}

// AlreadyVisited returns true if link is already visited.
func (m *mapper) AlreadyVisited(l myLink) bool {
	_, exists := m.Visited[l.URL]
	return exists
}

// IsStartAnchor returns true if an html.Token is a starting href.
// <a href="example.net">
func IsStartAnchor(tk html.Token) bool {
	return tk.Data == "a"
}

// GetURL returns the response from GET request in form of a io.Reader.
// See if we can bypass the response staying open forever.
func GetURL(url string) (io.Reader, error) {
	myLog.Printf("Started http.GET(%v)\n", url)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	defer myLog.Printf("Finished http.GET(%v)\n", url)

	return resp.Body, nil
}
