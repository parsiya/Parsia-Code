# Gophercises - 2 - Create Your Own Adventure

## Problem

* https://github.com/gophercises/cyoa
* https://gophercises.com/exercises/cyoa

## Solutions

* [Normal](normal): Implement the webapp.
* [Bonus](bonus)
    * Cli mode. Use `--cli`.
    * Set alternate starting page with `--home intro`.
    * Change the story file with `--book gopher.json`.
    * Change the webapp port with `--port 1234`.''

## Lessons Learned

### JSON to Objects Mappings

Maps to a `[]object` or array of objects:

``` json
[
    { 
        "key1": "value1",
        "key2": "value2"
    },
    { 
        "key1": "value3",
        "key2": "value4"
    }
]
```

Maps to a map of `[string]object`

``` json
{
	"object1": {
		"key1": "value1",
		"key2": "value2"
	},
	"object2": {
		"key1": "value3",
		"key2": "value4"
	}
}
```

### "html/template"

* https://golang.org/pkg/html/template/
* Same as Hugo's templates. So I already knew them.

### "text/template"

* https://golang.org/pkg/text/template/
* Very similar to HTML templates but used for manipulating text.
* Use instead of a lot of `fmt.Sprintf`s.