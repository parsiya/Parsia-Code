# Gophercises - 9 - Deck of Cards

## Problem

* https://github.com/gophercises/deck
* https://gophercises.com/exercises/deck


## Solution

* [deck/main.go](deck/main.go): Package.

## Lessons Learned

### Stringer package
Stringer package can generate `String()` for types. In this case, we can use it to make one for `Suit` and `Value` types.

* `go get golang.org/x/tools/cmd/stringer`
* go doc with example: https://godoc.org/golang.org/x/tools/cmd/stringer

1. Add the following on top of the file with the types (in this case `deck/card.go`).
   ```
   //go:generate stringer -type=Suit,Value
   ```
2. Run `go generate` inside the `deck` directory.
3. It will create a file named `suit_string.go`.
4. Now we can call `Suit.String()` and it will return a string.