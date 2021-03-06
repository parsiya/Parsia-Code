// This file is from the previous exercise with an extra line in main to add
// the debug handler. The debug handler and all other functions are in debug.go
package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime/debug"
)

var verbose bool

func main() {

	verbose = true

	mux := http.NewServeMux()
	mux.HandleFunc("/panic/", panicDemo)
	mux.HandleFunc("/panic-after/", panicAfterDemo)
	mux.HandleFunc("/", hello)
	mux.HandleFunc("/debug/", debugHandler) // Added in exercise 15.
	log.Fatal(http.ListenAndServe(":3000", recoverME(mux)))
}

// recoverMe recovers from a panic, returns 500 to browser but prints the
// stack trace to standard output.
func recoverME(app http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				stk := debug.Stack()
				var errorString string
				if verbose {
					fmt.Println(string(stk))
					ht1 := trace2HTML(string(stk)) // Add HTML to the thing.
					errorString = fmt.Sprintf("<H1>Error</H1>\n%s", ht1)
				} else {
					errorString = "Error"
				}
				// Copy string to w, using this instead of http.Error because
				// http.Error does not support HTML and only raw text.
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, errorString)
				// http.Error(w, errorString, http.StatusInternalServerError)
			}
		}()
		myRW := myResponseWriter{ResponseWriter: w}
		app.ServeHTTP(&myRW, r)
		myRW.Flusher()
	}
}

func panicDemo(w http.ResponseWriter, r *http.Request) {
	funcThatPanics()
}

func panicAfterDemo(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "<h1>Hello!</h1>")
	funcThatPanics()
}

func funcThatPanics() {
	panic("Oh no!")
}

func hello(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "<h1>Hello!</h1>")
}

// Custom http.ResponseWriter
// See here: https://www.reddit.com/r/golang/comments/7p35s4/how_do_i_get_the_response_status_for_my_middleware/
type myResponseWriter struct {
	http.ResponseWriter
	status int
	msg    [][]byte
}

// WriteHeader adds a custom status header to our response.
func (r *myResponseWriter) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// Write implements Write.
// Should return the number of bytes written and any error.
func (r *myResponseWriter) Write(b []byte) (int, error) {
	r.msg = append(r.msg, b)
	return len(b), nil
}

// Next is to implement more interfaces like Hijacker and Flusher.
// Hijack
func (r *myResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hi, exists := r.ResponseWriter.(http.Hijacker)
	if !exists {
		return nil, nil, fmt.Errorf("no hijacker for you")
	}
	return hi.Hijack()
}

// Flusher
func (r *myResponseWriter) Flusher() {
	// This should not be necessary, but let's check the status and add it.
	if r.status != 0 {
		r.ResponseWriter.WriteHeader(r.status)
	}
	for _, m := range r.msg {
		// Write everything to response.
		r.ResponseWriter.Write(m)
	}
}
