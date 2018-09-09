package main

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

// Simple HTML template.
var webTemplate = `
<!DOCTYPE html>
<html>
  <head>
    <title>Adventure Book</title>
  </head>
  <body>
    <h1>{{ .Title }}</h1>
      {{ range .Story }}
        <p>{{.}}</p>
      {{ end }}
      {{ if .Options }}
        <ul>
        {{ range .Options }}
          <li><a href="/{{ .Arc }}">{{ .Text }}</a></li>
        {{ end }}
        </ul>
      {{ else }}
        <h1>Fin</h1>
      {{ end }}
  </body>
</html>
`

// Page represents the contents of a page.
type Page struct {
	Title   string   `json:"title"`
	Story   []string `json:"story"`
	Options []Opt    `json:"options"`
}

// Opt is an option for a page. Each option has a text and a destination.
type Opt struct {
	Text string `json:"text"`
	Arc  string `json:"arc"`
}

// myHandler implements http.Handler and handles the stories.
type myHandler struct {
	stories map[string]Page
	tpl     *template.Template
}

// Init populates the handler with the template t and stories m.
func (m *myHandler) Init(t string, s map[string]Page) error {

	m.stories = s

	var err error
	m.tpl, err = template.New("adventure game").Parse(t)
	if err != nil {
		return err
	}
	return nil
}

// https://golang.org/pkg/net/http/#Handler
// Must implement ServeHTTP(ResponseWriter, *Request).
// ServeHTTP serves the adventure book.
func (m myHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	p := r.URL.Path

	switch p {
	case "":
		fallthrough
	case "/":
		p = "intro"
	default:
		// Remove whitespace at the end of URL.
		p = strings.Trim(p, " ")

		// Remove preceding "/" if any.
		p = strings.TrimLeft(p, "/")
	}

	if page, exists := m.stories[p]; exists {
		if err := m.tpl.Execute(w, page); err != nil {
			fmt.Printf("error %v", err)
		}
	}
}
