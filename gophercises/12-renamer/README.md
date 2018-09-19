# Gophercises - 12 - File Renaming Tool

## Problem

* https://github.com/gophercises/renamer
* https://gophercises.com/exercises/renamer


## Solution

* [dialog](dialog) is a package to facilitate printing and getting user choices.
* [renamer](renamer) is the file renaming package.
* [main0.go](main0.go), [main1.go](main1.go), and [main2.go](main2.go) are drafts created during the lesson.
* [main.go](main.go) is the main file and uses both packages.

## Lessons Learned

### filepath.Walk
[filepath.Walk](https://golang.org/pkg/path/filepath/#Walk) can be used to traverse all files in a path recursively.

``` go
func Walk(root string, walkFn WalkFunc) error
```

`root` is the starting path and `WalkFunc` is a function that is called after visiting each file:

``` go
func(path string, info os.FileInfo, err error) error
```

[os.FileInfo](https://golang.org/pkg/os/#FileInfo) has a bunch of methods:

``` go
// A FileInfo describes a file and is returned by Stat and Lstat.
type FileInfo interface {
	Name() string       // base name of the file
	Size() int64        // length in bytes for regular files; system-dependent for others
	Mode() FileMode     // file mode bits
	ModTime() time.Time // modification time
	IsDir() bool        // abbreviation for Mode().IsDir()
	Sys() interface{}   // underlying data source (can return nil)
}
```

So to list everything in a directory ([main0.go](main0.go)):

``` go
func main() {

	// Make a list of all files in sample.
	err := filepath.Walk("sample", walkWithMe0)
	if err != nil {
		log.Println(err)
	}
}

// walkWithMe0 returns info about files.
func walkWithMe0(path string, info os.FileInfo, err error) error {

	// Now we can do what we want with os.FileInfo.
	fmt.Printf("Visiting %v\n", info.Name())
	return nil
}
```

`walkWithMe` is good for listing things but bad for saving info. To do so, we pass a function that returns an anonymous `filepath.WalkFunc` (same signature as walkWithMe) and then pass a pointer to that function.

[main1.go](main1.go):

``` go
func main() {

	var f []string
	// Make a list of all files in sample.
	err := filepath.Walk("sample", walkWithMe1(&f))
	if err != nil {
		log.Println(err)
	}

	for _, v := range f {
		fmt.Println(v)
	}
}

// walkWithMe1 stores the list of files in a slice.
func walkWithMe1(f *[]string) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		// Return error if we got an error.
		if err != nil {
			return err
		}
		*f = append(*f, path)
		return nil
	}
}
```

This lists all files. If we want to only list files (or directories) we can use [info.IsDir()](https://golang.org/pkg/os/#FileInfo). [main2.go](main2.go):


``` go
// walkWithMe2 stores the list of files but no directories in a slice.
func walkWithMe2(f *[]string) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		// Return error if we got an error.
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		*f = append(*f, path)
		fmt.Printf("%+v\n", info.Sys())
		return nil
	}
}
```

On Windows [*syscall.Win32FileAttributeData](https://golang.org/pkg/syscall/?GOOS=windows&GOARCH=amd64#Win32FileAttributeData).


[info.path.Ext()](https://golang.org/pkg/path/filepath/#Ext) returns the extension which just does some text processing on path. **It returns the period (e.g. ".txt").**

[info.path.Match](https://golang.org/pkg/path/filepath/#Match) can be used to match filenames.