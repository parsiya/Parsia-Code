package main

import (
	"os"

	svg "github.com/ajstarks/svgo"
)

// drawSVG recreates our bar chart using svgo.
func drawSVG(imgFile string, data []int) error {

	width, height := len(data)*80+20, 100

	f, err := os.Create(imgFile)
	if err != nil {
		return err
	}

	canvas := svg.New(f)
	canvas.Start(width, height)
	for index, value := range data {
		canvas.Rect(index*80+10, height-value, 60, value, "fill:rgb(0,128,0)")
	}
	canvas.End()
	return nil
}

// Usage represents usage for a month.
type Usage struct {
	Month string
	Usage int
}

// usageSVG creates a bar chart for usage with labels.
func usageSVG(imgFile string, data []Usage) error {
	width, height := len(data)*80+20, 300
	labelHeight := 50
	height = height - labelHeight

	f, err := os.Create(imgFile)
	if err != nil {
		return err
	}

	// Normalize the height.
	// First we need to find the max.
	max := MaxUsage(data).Usage

	canvas := svg.New(f)
	canvas.Start(width, height)
	for index, value := range data {
		per := value.Usage * height / max
		// Draw the bars.
		canvas.Rect(index*80+10, height-per, 60, per, "fill:rgb(0,128,0)")

		// Draw the label.
		canvas.Text(index*80+40, height-10, value.Month, "font-size:15pt;black;text-anchor:middle")
	}

	// Create the line at the bottom.
	canvas.Line(0, height, width, height, "stroke: rgb(0,0,0); stroke-width:2")

	canvas.End()
	return nil
}

// MaxUsage find the object with highest usage.
func MaxUsage(data []Usage) Usage {
	// max.Usage initializes to zero.
	var max Usage
	for _, u := range data {
		if u.Usage > max.Usage {
			max = u
		}
	}
	return max
}
