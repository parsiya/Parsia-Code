package main

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	textTemplate "text/template"
)

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

// -----

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

// webHandler implements http.Handler and handles the stories.
type webHandler struct {
	stories map[string]Page
	tpl     *template.Template
	txt     *textTemplate.Template
	home    string // home page
}

// Init populates the handler with stores and the template t.
func (wb *webHandler) Init(t string, s map[string]Page, home string) error {

	wb.stories = s

	if _, exists := wb.stories[home]; exists {
		wb.home = home
	} else {
		return fmt.Errorf("%s is not a valid node, please check the JSON file", home)
	}

	var err error
	wb.tpl, err = template.New("adventure game").Parse(t)
	if err != nil {
		return err
	}
	return nil
}

// https://golang.org/pkg/net/http/#Handler
// Must implement ServeHTTP(ResponseWriter, *Request).
// ServeHTTP serves the adventure book.
func (wb webHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	p := r.URL.Path

	switch p {
	case "":
		fallthrough
	case "/":
		p = wb.home
	default:
		// Remove whitespace at the end of URL.
		p = strings.Trim(p, " ")

		// Remove preceding "/" if any.
		p = strings.TrimLeft(p, "/")
	}

	if page, exists := wb.stories[p]; exists {
		if err := wb.tpl.Execute(w, page); err != nil {
			fmt.Printf("error %v", err)
		}
	}
}

// -----

// Simple cli template.
var cliTemplate = `
Title: {{ .Title }}

{{ range .Story }}
{{ . }}
{{ end -}}
{{ if .Options }}
{{ range .Options }}
 - {{ .Arc }} : {{ .Text }}
{{- end }}

What do you do?
{{- else }}
    The End
{{- end -}}
`

// cliHandler handles the text stories.
type cliHandler struct {
	stories map[string]Page
	txt     *textTemplate.Template
	home    string // home page
}

// Init populates the handler with stories and the template.
func (c *cliHandler) Init(t string, s map[string]Page, home string) error {

	c.stories = s

	if _, exists := c.stories[home]; exists {
		c.home = home
	} else {
		return fmt.Errorf("%s is not a valid node, please check the JSON file", home)
	}

	var err error
	c.txt, err = textTemplate.New("adventure game").Parse(t)
	if err != nil {
		return err
	}
	return nil
}

// ExecuteTemplate executes a template with a given object and returns
// the result as string.
func (c cliHandler) ExecuteTemplate(p string) string {

	if page, exists := c.stories[p]; exists {
		buf := bytes.NewBufferString("")
		c.txt.Execute(buf, page)
		return buf.String()
	}
	return ""
}

// HasOption checks if a page has a certain option.
func (c cliHandler) HasOption(p string, o string) bool {
	o = strings.Trim(o, " ")
	if page, exists := c.stories[p]; exists {
		for _, opt := range page.Options {
			if strings.ToLower(opt.Arc) == strings.ToLower(o) {
				return true
			}
		}
	}
	return false
}

// IsEnding checks if the page is an ending.
// Endings do not have any options.
func (c cliHandler) IsEnding(p string) bool {
	if page, exists := c.stories[p]; exists {
		if len(page.Options) == 0 {
			return true
		}
	}
	return false
}
