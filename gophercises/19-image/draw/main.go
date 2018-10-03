package main

import (
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
)

func main() {
	data := []int{10, 33, 73, 64}

	width, height := len(data)*80+20, 100
	rect := image.Rect(0, 0, width, height)
	im := image.NewRGBA(rect)

	background := color.RGBA{0xFF, 0xFF, 0xFF, 0xFF}
	green := color.RGBA{0, 128, 0, 0xFF}

	// Now we can use the draw package to fill the background with the
	// same color instead of nested fors.
	// This essentially creates an unlimited white image (uniform) and copies it
	// over the original image.
	// Image.Point doesn't matter here because uniform is unlimited. If it was
	// not, it would be the top-left of the rectangle grabbed from source.
	draw.Draw(im, rect, image.NewUniform(background), image.Point{0, 0}, draw.Src)

	// Manipulate the image.

	// Draw the bars.
	for index, value := range data {
		x0, y0 := (index*80 + 10), 100-value
		x1, y1 := (index+1)*80, 100
		re := image.Rect(x0, y0, x1, y1)
		draw.Draw(im, re, image.NewUniform(green), image.Point{0, 0}, draw.Src)
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
