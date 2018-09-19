package renamer

import (
	"fmt"
	"os"
	"path/filepath"
)

// MyFile represents each file in the path.
type MyFile struct {
	info os.FileInfo
	path string
}

// Ext returns the extension of a file.
func (m MyFile) Ext() string {
	return filepath.Ext(m.info.Name())
}

// Name returns the name of a file.
func (m MyFile) Name() string {
	return m.info.Name()
}

// String print the contents of MyFile.
func (m MyFile) String() string {
	return fmt.Sprintf("%v", m.path)
}

// Matched returns a slice of files that match the shell file name pattern.
func Match(pattern string, allFiles []MyFile) []MyFile {
	var matched []MyFile
	for _, f := range allFiles {
		match, err := filepath.Match(pattern, f.Name())
		if err != nil {
			continue
		}
		if match {
			matched = append(matched, f)
		}
	}
	return matched
}

// RenameExtension renames all files with one extension to another.
// Returns the number of files renamed and errors if unsuccessful.
func RenameExtension(path, oldExt, newExt string) (int, error) {
	c := 0
	if err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Becasuse filepath.Ext returns the period, we need to add it to the
		// input.

		if oldExt[0] != '.' {
			oldExt = "." + oldExt
		}
		if newExt[0] != '.' {
			newExt = "." + newExt
		}

		// If it's a file with the old extension (not sure how messing with
		// directories will behave).
		if !info.IsDir() {
			// Can also use filepath.Match here.
			ext := filepath.Ext(info.Name())
			if ext == oldExt {
				// Remove the last len(ext) from path and add the new extension
				// before the rename.
				newPath := path[:len(path)-len(ext)] + newExt
				if err := os.Rename(path, newPath); err != nil {
					return err
				}
				c++
			}
		}
		return nil
	}); err != nil {
		return 0, err
	}
	return c, nil
}

// GetAllFileInfo returns a []MyFile with only files in a specific path.
func GetAllFileInfo(p string) ([]MyFile, error) {
	var files []MyFile
	if err := filepath.Walk(p, walkWithMeAndGetInfo(&files)); err != nil {
		return nil, err
	}
	return files, nil
}

// walkWithMeAndGetInfo stores file info.
func walkWithMeAndGetInfo(f *[]MyFile) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		*f = append(*f, MyFile{info: info, path: path})
		return nil
	}
}

// GetAllFilenames returns a []string with only files in a specific path.
func GetAllFilenames(p string) ([]string, error) {
	var files []string
	if err := filepath.Walk(p, walkWithMe(&files)); err != nil {
		return nil, err
	}
	return files, nil
}

func walkWithMe(f *[]string) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		*f = append(*f, path)
		return nil
	}
}

// PathExists returns true if path exists in the file system.
// Returns true for both files and directories.
func PathExists(p string) bool {
	if _, err := os.Stat(p); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}
