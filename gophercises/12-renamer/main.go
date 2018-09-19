package main

import (
	"fmt"

	"github.com/parsiya/Parsia-Code/gophercises/12-renamer/dialog"
	"github.com/parsiya/Parsia-Code/gophercises/12-renamer/renamer"
)

func main() {

	fmt.Println("Enter the path")
	var path string
	fmt.Scanln(&path)

	if !renamer.PathExists(path) {
		fmt.Println("Path does not exist.")
		return
	}

	fmt.Println("Enter the shell file name pattern:")
	var pattern string
	fmt.Scanln(&pattern)

	allFiles, err := renamer.GetAllFileInfo(path)
	if err != nil {
		panic(err)
	}

	matched := renamer.Match(pattern, allFiles)

	if len(matched) == 0 {
		fmt.Println("Your match did not return any results.")
		return
	}

	fmt.Printf("Your pattern \"%v\" returned %v matches:\n\n", pattern, len(matched))
	for _, m := range matched {
		fmt.Println(m)
	}

	var d dialog.Dialog
	d.Question = "What do you want to do?"
	d.AddChoices([]string{"Rename extension", "Quit"})

	c := d.Start()

	if c != 0 {
		return
	}

	var newExt string
	fmt.Println("Enter the new extension:")
	fmt.Scanln(&newExt)

	count, err := renamer.RenameExtension(path, matched[0].Ext(), newExt)
	if err != nil {
		panic(err)
	}
	fmt.Printf("You modified %v files.", count)
}
