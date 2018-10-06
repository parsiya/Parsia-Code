package main

import (
	"fmt"
	"strconv"

	"github.com/jung-kurt/gofpdf"
)

func main() {

	// Change papersize to letter because 'Murica is special!
	pdf := gofpdf.New(gofpdf.OrientationPortrait, gofpdf.UnitPoint, gofpdf.PageSizeLetter, "")

	// Get page size. It depends on the unit defined in New.
	w, h := pdf.GetPageSize()
	fmt.Println(w, h)

	pdf.AddPage()
	pdf.MoveTo(0, 0)
	pdf.SetFont("Courier", "B", 16)
	pdf.SetTextColor(255, 0, 0)

	// To get the line height based on font size (which is important for going
	// to the next lines), use pdf.GetFontSize()
	// GetFontSize returns the size of the current font in points followed by the
	// size in the unit of measure specified in New(). The second value can be used
	// as a line height value in drawing operations.
	spt, lpt := pdf.GetFontSize()
	fmt.Printf("font size: 16, fontsize-point: %f, fontsize-unit: %f\n", spt, lpt)

	// So if we want the next line to be visible but at the top of the page,
	// we need to start it from lpt.
	pdf.Text(0, lpt, "Line one in red")

	// To get to next line, we can use MoveTo.
	pdf.MoveTo(0, lpt*2)

	// To get the coordinates we can do this.
	curX, curY := pdf.GetXY()

	// Modify and render next line.
	pdf.SetTextColor(0, 255, 0)
	pdf.Text(curX, curY, "Text two")

	// We can also use cells. Cells are like textboxes.
	pdf.MoveTo(0, lpt*2)
	curX, curY = pdf.GetXY()
	pdf.SetTextColor(0, 0, 255)
	pdf.Cell(curX, curY, "Cell line in blue")

	// Draw color is the color of the lines (e.g. edges of shapes.)
	pdf.SetDrawColor(0, 255, 0)

	// Fill color is the color inside the edges.
	pdf.SetFillColor(0, 0, 255)

	// Create a rectangle.
	// F in style means fill, D in style means draw.
	// We already set draw and fill color.
	pdf.Rect(100, 100, 100, 100, "FD")

	// Create arbitrary looking shapes with polygon.
	// Point type is
	// type PointType struct {
	// 	X, Y float64
	// }
	// Order is important, last point is connected back to the first point.
	// This creates a square.
	points := []gofpdf.PointType{
		{140, 140},
		{240, 140},
		{240, 240},
		{140, 240},
	}
	pdf.Polygon(points, "FD")

	// Add images.
	// First we need to create imageoptions.
	// type ImageOptions struct {
	// 	ImageType             string
	// 	ReadDpi               bool
	// 	AllowNegativePosition bool
	// }
	// ImageType: Type of image (e.g. jpeg, jpg, gif, png). If empty, uses extension.
	// ReadDpi: If true, read the DPI from image. Default is false.
	// AllowNegativePosition: Did not understand what it does, keeping at false.
	opt1 := gofpdf.ImageOptions{
		ImageType:             "jpg",
		ReadDpi:               true,
		AllowNegativePosition: false,
	}

	// Images can have links, if internal, create a link with AddLink() and put
	// the resulting number in the parameter one before last, otherwise pass as
	// 0 and put the external link URL in the last parameter.
	pdf.ImageOptions("img/gopher1.jpg", 240, 80, 0, 0, true, opt1, 0, "https://example.net")

	pdf.MoveTo(60, 270)
	// Multicell creates a text cell that wraps and has a specific dimension.
	// In this case we are creating 140 width. Second parameter is height of each line.
	// So we set it to line height for current font size.
	// borderStr specifies (4th param)
	pdf.MultiCell(
		140, // Width of cell.
		lpt, // Height of each line, so it's set to line height for current font size.

		"This is a long text that is supposed to wrap around the cell, more text and text", // Text

		"0", // how the cell border will be drawn. An empty string
		// indicates no border, "1" indicates a full border, and one or more of "L",
		// "T", "R" and "B" indicate the left, top, right and bottom sides of the
		// border.

		"LT", // alignStr specifies how the text is to be positioned within the cell.
		// Horizontal alignment is controlled by including "L", "C" or "R" (left,
		// center, right) in alignStr. Vertical alignment is controlled by including
		// "T", "M", "B" or "A" (top, middle, bottom, baseline) in alignStr. The default
		// alignment is left middle.

		false, // fill is true to paint the cell background or false to leave it transparent.
	)

	drawGrid(pdf)
	if err := pdf.OutputFileAndClose("hello.pdf"); err != nil {
		panic(err)
	}
}

// drawGrid draws a grid in the PDF for better navigation.
func drawGrid(pdf *gofpdf.Fpdf) {
	w, h := pdf.GetPageSize()
	pdf.SetFont("courier", "B", 10)
	pdf.SetTextColor(80, 80, 80)
	pdf.SetDrawColor(125, 125, 125)
	_, lpt := pdf.GetFontSize()

	for x := 0.0; x < w; x += (w / 20.0) {
		pdf.Line(x, 0, x, h)
		pdf.Text(x, lpt, strconv.Itoa(int(x)))
	}

	for y := 0.0; y < h; y += (h / 20.0) {
		pdf.Line(0, y, w, y)
		pdf.Text(lpt, y, strconv.Itoa(int(y)))
	}
}
