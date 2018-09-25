// debug.go contains all the code for exercise 15.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/alecthomas/chroma/formatters/html"
	"github.com/alecthomas/chroma/lexers"
	"github.com/alecthomas/chroma/quick"
	"github.com/alecthomas/chroma/styles"
)

// debugHandler renders and returns the source file in the "file" parameter.
func debugHandler(w http.ResponseWriter, r *http.Request) {

	// Returns a map of string slices for each param.
	// https://golang.org/pkg/net/url/#URL.Query
	// type Values map[string][]string
	vals := r.URL.Query()

	// Then we can call vals.Get("key") to get the first value.
	// https://golang.org/pkg/net/url/#Values.Get
	if fi := vals.Get("file"); fi != "" {

		// Read the file.
		source, err := GetFile(fi)
		if err != nil {
			fmt.Fprint(w, err.Error())
			return
		}

		// Optionally support a style parameter and use that for highlighting.
		// List is at https://xyproto.github.io/splash/docs/.
		styleText := strings.ToLower(vals.Get("style"))

		// If file exists, highlight it with Chroma. Chroma should be familiar
		// if you use the Hugo static website generator.

		// highlighted, err := QuickHighlighter(fi, source, styleText)
		// if err != nil {
		// 	fmt.Fprint(w, err.Error())
		// 	return
		// }

		// Get line to highlight line, otherwise highlight 0.
		l := vals.Get("line")
		lineno, err := strconv.Atoi(l)
		if err != nil {
			lineno = 0
		}

		highlighted, err := Highlighter(fi, source, styleText, lineno)
		if err != nil {
			fmt.Fprint(w, err.Error())
			return
		}

		fmt.Fprint(w, highlighted)
		// Return so we do not get the usage string in the end.
		return
	}

	// Return some random text if no params are provided.
	usageString := `<html><body>
	Create your queries in form of file path and optional style:

	<a href="http://localhost:3000/debug?file=main.go&style=monokai">http://localhost:3000/debug?file=main.go&style=monokai</a>
	</body></html>`

	fmt.Fprint(w, usageString)
}

// GetFile reads the file and returns a string of the contents.
func GetFile(fi string) (string, error) {
	// Assume path is either relative to where we are or absolute.
	f, err := os.Open(fi)
	if err != nil {
		return "", err
	}
	// Read the file.
	sourceBytes, err := ioutil.ReadAll(f)
	if err != nil {
		return "", err
	}
	return string(sourceBytes), nil
}

// QuickHighlighter writes the highlighted code to an io.Writer similar to
// quick.Highlight.
func QuickHighlighter(fileName, source, style string) (string, error) {
	// If styleText does not match any style, it will return "swapoff."
	// So we check if we entered "swapoff" and if not, we will change it to
	// "solarized-dark."
	st := styles.Get(style)
	if st.Name == "swapoff" && style != "swapoff" {
		st = styles.Get("solarized-dark")
	}

	// While we already know we are looking at Go code, we are going to
	// Chroma's lexer.Analyze to get the lexer based on extension.
	// https://github.com/alecthomas/chroma#identifying-the-language
	lexer := lexers.Match(fileName)
	// lexer is nil if no match could be found.
	if lexer == nil {
		// So we use the Analyse function.
		lexer = lexers.Analyse(source)
	}

	// Default to Go, if neither process detected a lexer.
	if lexer == nil {
		lexer = lexers.Get("go")
	}

	// https://github.com/alecthomas/chroma#quick-start
	// err := quick.Highlight(os.Stdout, someSourceCode, "go", "html", "monokai")
	// Highlight conveniently writes to an io.Writer which we pass to w.
	// quick.Highlight sacrifices some control.
	// For example, tab space in the "html" formatter is set to 8.

	var b bytes.Buffer
	wri := bufio.NewWriter(&b)

	if err := quick.Highlight(wri, source, lexer.Config().Name, "html", st.Name); err != nil {
		return "", err
	}

	return b.String(), nil
}

// Highlighter is a more hands-on version of QuickHighlighter and comes with
// lines highlight support.
func Highlighter(fileName, source, style string, lineno int) (string, error) {
	// If styleText does not match any style, it will return "swapoff."
	// So we check if we entered "swapoff" and if not, we will change it to
	// "solarized-dark."
	st := styles.Get(style)
	if st.Name == "swapoff" && style != "swapoff" {
		st = styles.Get("solarized-dark")
	}

	// While we already know we are looking at Go code, we are going to
	// Chroma's lexer.Analyze to get the lexer based on extension.
	// https://github.com/alecthomas/chroma#identifying-the-language
	lexer := lexers.Match(fileName)
	// lexer is nil if no match could be found.
	if lexer == nil {
		// So we use the Analyse function.
		lexer = lexers.Analyse(source)
	}
	// Default to Go, if neither process detected a lexer.
	if lexer == nil {
		lexer = lexers.Get("go")
	}

	// Create the range variable for highlighting line numbers.
	// It's of type [][2]int.
	hl := [][2]int{[2]int{lineno, lineno}}
	// We are only highlighting one line so both items in the [2]int array
	// are the same. If we wanted to highlight a range, we would have used
	// start and finish line numbers.

	// Create a customized html.Formatter.
	// We can also get rid of the 8 tab space now.
	formatter := html.New(html.Standalone(), html.WithLineNumbers(),
		html.HighlightLines(hl), html.TabWidth(4))

	// Get iterator.
	it, err := lexer.Tokenise(nil, source)
	if err != nil {
		return "", err
	}

	var b bytes.Buffer
	wri := bufio.NewWriter(&b)

	if err := formatter.Format(wri, st, it); err != nil {
		return "", err
	}

	return b.String(), nil
}

// trace2HTML converts a string containing the stack trace to HTML by parsing
// the links and converting them to /debug/ links.
// Simple stack looks like:
// Error
// goroutine 65 [running]:
// runtime/debug.Stack(0xc04241fb50, 0x827ba0, 0x9ebd60)
// 	C:/Go/src/runtime/debug/stack.go:24 +0xae
// Line with the source code starts with a tab and has a :.
func trace2HTML(trace string) string {
	var output strings.Builder

	scanner := bufio.NewScanner(strings.NewReader(trace))
	for scanner.Scan() {
		// If it contains ".go:" it's a source line.
		if strings.Contains(scanner.Text(), ".go:") {
			// Split by strings.Fields
			line := strings.Fields(scanner.Text())
			// Now line[0] contains the line and line[1] contains the offset (e.g. 0xae)
			li := strings.Split(line[0], ":")
			// Now li[len(li)-1] is the line number and line[0][:len(li[1]-1)] is the rest.
			lineno := li[len(li)-1]
			link := fmt.Sprintf("\t<a href=\"http://localhost:3000/debug/?file=%s&line=%s\">%s</a>",
				line[0][:len(line[0])-len(lineno)-1], lineno, scanner.Text())

			// Add to output in a new line.
			output.WriteString(link + "</br>")
		} else {
			output.WriteString(scanner.Text() + "</br>")
		}
	}
	return output.String()
}
