# Gophercises - 5 - Sitemap Builder

## Problem

* https://github.com/gophercises/sitemap
* https://gophercises.com/exercises/sitemap

## Solutions

* Normal-Bonus: Normal and bonus. Works and has depth. Can log to file

    ```
    $ go run main.go sitemap.go --help
    -depth int
            specify sitemap depth (default 2147483647)
    -file string
            name of xml file
    -log
            display logs
    -url string
            staring URL - must be provided
    ```

## Lessons Learned

### net.URL

* https://golang.org/pkg/net/url/
* There are tons of great methods.
* Convert a string to URL: `Parse(rawurl string) (*URL, error)`
* URL will give you tons of utilities:
    ``` go
    type URL struct {
        Scheme     string
        Opaque     string    // encoded opaque data
        User       *Userinfo // username and password information
        Host       string    // host or host:port
        Path       string    // path (relative paths may omit leading slash)
        RawPath    string    // encoded path hint (see EscapedPath method)
        ForceQuery bool      // append a query ('?') even if RawQuery is empty
        RawQuery   string    // encoded query values, without '?'
        Fragment   string    // fragment for references, without '#'
    }
    ```
* `IsAbs()` returns true if path is absolute.
* `Hostname()` returns host and port.
* Contents are case-sensitive.
* Get the complete URL with `URL.String()`.

### ioutil.Discard

* `var Discard io.Writer = devNull(0)`

### Break/Continue to Label

* Really helps when inside a select which is inside an infinite loop.
* Designate labels as usual.
* `break` or `continue` to label.
  ``` go
  Mainloop:
	for {
		select {
		case whatever:
			//
		default:
			// Do what you want
			break Mainloop
		}
	}
  ```