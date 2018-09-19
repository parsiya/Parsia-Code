package renamer

import "fmt"

func main() {

	//Make a list of all files in sample.

	files, err := GetAllFilenames("sample")
	if err != nil {
		panic(err)
	}
	for _, v := range files {
		fmt.Println(v)
	}

	// Change txt to md
	c, err := RenameExtension("..\\sample", "txt", "md")
	if err != nil {
		panic(err)
	}
	fmt.Printf("%v files modified.\n", c)

	files, err = GetAllFilenames("sample")
	if err != nil {
		panic(err)
	}
	for _, v := range files {
		fmt.Println(v)
	}

}
