# Gophercises - 15 - Development Panic/Recover Middleware with Chroma

## Problem

* https://github.com/gophercises/recover_chroma
* https://gophercises.com/exercises/recover_chroma


## Solution

* [main.go](main.go): Code and panic highlight

## Lessons Learned

### http.Error Only Support Plaintext
When doing `http.Error` the result will be sent as text and not `text/html`.

Use `fmt.Fprintf(w, ...)` instead.

### Chroma
Already familiar because it's used in Hugo.

`quick.Highlight` sacrifices control but does things quickly:

``` go
quick.Highlight(os.Stdout, someSourceCode, "go", "html", "monokai")
```

For more control use `formatter.Format(w io.Writer, s *Style, it Iterator)`:

``` go
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
```