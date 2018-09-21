# Gophercises - 14 - Panic/Recover Middleware

## Problem

* https://github.com/gophercises/recover
* https://gophercises.com/exercises/recover


## Solution

* [main.go](main.go): Implemented everything including Flusher and Hijack.

## Lessons Learned

### Print Stacktrace

* [debug.Stack()](https://golang.org/pkg/runtime/debug/#Stack): Returns a `[]byte` (remember to convert to string before printing).
* [runtime.Stack(buf []byte, all bool) int](https://golang.org/pkg/runtime/#Stack): Pass a `[]byte` that gets filled.

### Custom http.ResponseWriter
See this:
* https://upgear.io/blog/golang-tip-wrapping-http-response-writer-for-middleware/

### Embed
Embed stuff in structs to use them.

``` go
type myRW struct {
    http.ResponseWriter
}
```

### Type Assertion

* https://tour.golang.org/methods/15

``` go
t, ok := i.(T)
if ok {
    // i.T is implemented and stored in T
}
```