package main

import (
	"image"
	"image/color"
	"image/png"
	"os"
)

func main() {
	data := []int{10, 33, 73, 64}

	width, height := len(data)*80+20, 100
	rect := image.Rect(0, 0, width, height)
	im := image.NewRGBA(rect)

	// Manipulate the image.

	// First set everything to white.
	for i := 0; i < width; i++ {
		for j := 0; j < height; j++ {
			im.SetRGBA(i, j, color.RGBA{0xFF, 0xFF, 0xFF, 0xFF})
		}
	}

	// Draw the bars.
	for index, value := range data {
		for i := index*80 + 10; i < (index+1)*80; i++ {
			for j := 100; j >= 100-value; j-- {
				im.Set(i, j, color.RGBA{100, 100, 100, 0xFF})
			}
		}
	}

	f, err := os.Create("img.png")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Encode the image to png.
	if err := png.Encode(f, im); err != nil {
		panic(err)
	}

}
