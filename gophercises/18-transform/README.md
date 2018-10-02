# Gophercises - 18 - Image Transformer

## Problem

* https://github.com/gophercises/transform
* https://gophercises.com/exercises/transform


## Solution

* [main.go](main.go): Main functionality.
* [primitive/primitive.go](primitive/primitive.go): Primitive package.

## Lessons Learned

### HTML Input type File
We can use something like this

``` html
<input type="file"
    id="upload" name="upload"
    accept="image/jpeg,image/png" />
```

This only shows files of type `jpeg` and `png`. We can also do `image/*` to show all images.

### Int to Enum
Assuming we have this enum:

``` go
type EnumType int

const (
	Zero Enum = iota
	One
	Two
	Three
)
```

We can convert an int to this type with `EnumType(2)`.

### http.Request.FormFile
Gets the first file in the param (usually POST body).

* https://golang.org/pkg/net/http/?#Request.FormFile

``` go
file, header, err := r.FormFile("upload")
```

* `file` can be used like any other file (hint: implements `io.Reader`).
    * https://golang.org/pkg/mime/multipart/#File
* `header` has info about the file like name and size.
    * https://golang.org/pkg/mime/multipart/#FileHeader

Response.PostForm is a map of `url.Values` (`map[string][]string`).