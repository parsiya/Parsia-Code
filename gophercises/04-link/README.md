# Gophercises - 4 - Link

## Problem

* https://github.com/gophercises/link
* https://gophercises.com/exercises/link

## Solutions

* [link](link/link.go): link package.
* [main](main.go): Use link package to extract links from HTML.

## Lessons Learned

### /x/net/html

* Read the package example: https://godoc.org/golang.org/x/net/html
* Token struct:
    ``` go
    type Token struct {
        Type     TokenType
        DataAtom atom.Atom
        Data     string
        Attr     []Attribute
    }
    ```
* `Type` can give us information about what kind of token it is. Important ones for this exercise are:
    * `StartTagToken`: `<a href>`
    * `EndTagToken`: `</a>`
    * `TextToken`: Text in between. Using text nodes will skip other elements inside the link.
* `Data` contains the data in the node.
    * Anchor tags: `a`.
    * Text nodes: The actual text of the node.
* Attribute is of type:
    ``` go
    type Attribute struct {
	    Namespace, Key, Val string
    }
    ```
* `Key` is the name of the attribute and `Value` is the value.
    * `<a href="example.net">`: `key` = `href` and `value` = `example.net`.

### Parse
Parse is easy.

* Go through the nodes. If you reach a start anchor tag, set the `capturing` flag to start capturing. Store the `href`.
* While capturing, add the text of every text node (trim all white space but add a space between nodes).
* After reaching the end anchor tag, stop capturing and store the link.
* Add link to the links slice.

Issues:

* Nested links are ignored. Child links are not stored and their text is stored as part of the parent link.
    * For an example run `go run main.go -f ex5.html`.
