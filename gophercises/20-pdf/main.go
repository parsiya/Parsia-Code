// Generate the course completion PDF.
package main

import (
	"fmt"
	"strconv"

	"github.com/jung-kurt/gofpdf"
)

const (
	bannerHeight = 70

	// Top-left and bottom-right banners' colors.
	banner2R = 122
	banner2G = 85
	banner2B = 102

	// Top-right and bottom-left banners' colors.
	banner1R = 103
	banner1G = 60
	banner1B = 79

	// Grey color.
	greyRGB = 113

	// "Certificate of Completion" location.
	certY = 100

	// "This certificate is awarded to" line.
	lineTwoY = 200

	// Recipient name line.
	lineThreeY = 250

	// "For successfully" line.
	lineFourY = 330

	// Date and instructor line.
	lineFiveY = 460

	// Line under date and instructor.
	lineSixY = 480

	// "Date" and "Instructor" line.
	lineSevenY = 480
)

func main() {
	pdf := gofpdf.New(gofpdf.OrientationLandscape, gofpdf.UnitPoint, gofpdf.PageSizeLetter, "")
	pdf.AddPage()

	w, h := pdf.GetPageSize()
	fmt.Println(w, h)

	// Draw top-left banner.
	topLeftPoints := []gofpdf.PointType{
		{0, 0},
		{0, bannerHeight},
		{w, 0},
	}
	pdf.SetFillColor(banner2R, banner2G, banner2B)
	pdf.Polygon(topLeftPoints, "F")

	// Draw bottom-right banner - same color as top-left.
	bottomRightPoints := []gofpdf.PointType{
		{w, h - bannerHeight},
		{0, h},
		{w, h},
	}
	pdf.Polygon(bottomRightPoints, "F")

	// Draw top-right banner.
	topRightPoints := []gofpdf.PointType{
		{0, 0},
		{w, 0},
		{w, bannerHeight},
	}
	pdf.SetFillColor(banner1R, banner1G, banner1B)
	pdf.Polygon(topRightPoints, "F")

	// Draw bottom-left banner - same color as top-right.
	bottomLeftPoints := []gofpdf.PointType{
		{0, h},
		{0, h - bannerHeight},
		{w, h},
	}
	pdf.Polygon(bottomLeftPoints, "F")

	// Write "Certificate of Completion."
	pdf.SetTextColor(0, 0, 0)
	pdf.SetFont("times", "B", 40)
	pdf.MoveTo(0, certY)
	_, lpt := pdf.GetFontSize()

	pdf.WriteAligned(0, lpt, "Certificate of Completion", "C")

	// "This certificate is awarded to" line.
	pdf.SetFont("Helvetica", "", 25)
	pdf.MoveTo(0, lineTwoY)
	_, lpt = pdf.GetFontSize()

	pdf.WriteAligned(0, lpt, "This certificate is awarded to", "C")

	// Recipient name line.
	pdf.SetFont("Times", "", 40)
	pdf.MoveTo(0, lineThreeY)
	_, lpt = pdf.GetFontSize()

	pdf.WriteAligned(0, lpt, "Parsia", "C")

	// "For successfully" line.
	pdf.SetFont("Helvetica", "", 25)
	pdf.MoveTo(0, lineFourY)
	_, lpt = pdf.GetFontSize()

	pdf.WriteAligned(0, lpt*1.5, "For successfully completing all twenty programming exercises in the Gophercises Go programming course.", "C")

	// Date and instructor line.
	pdf.SetFont("times", "", 18)
	_, lpt = pdf.GetFontSize()
	pdf.SetTextColor(greyRGB, greyRGB, greyRGB)
	pdf.MoveTo(150, lineFiveY)
	// Print date.
	pdf.WriteAligned(1, lpt, "10/06/2018", "C")

	// Print Instructor Name.
	pdf.MoveTo(600, lineFiveY)
	pdf.WriteAligned(1, lpt, "Jon Calhoun", "C")

	// Draw the line under date.
	pdf.SetFillColor(0, 0, 0)
	pdf.Line(118, lineSixY, 277, lineSixY)

	// Draw the line under instructor.
	pdf.Line(556, lineSixY, 732, lineSixY)

	// "Date"
	pdf.SetTextColor(greyRGB, greyRGB, greyRGB)
	pdf.MoveTo(180, lineSevenY)
	pdf.WriteAligned(1, lpt, "Date", "C")

	// "Instructor"
	pdf.MoveTo(610, lineSevenY)
	pdf.WriteAligned(1, lpt, "Instructor", "C")

	// Logo.
	logoOpts := gofpdf.ImageOptions{
		ReadDpi: true,
	}
	pdf.ImageOptions("logo.png", 346, lineSixY-50, 100, 100, false, logoOpts, 0, "")

	// DrawGrid(pdf)
	if err := pdf.OutputFileAndClose("certificate.pdf"); err != nil {
		panic(err)
	}
	fmt.Println("Done")
}

// DrawGrid draws a grid in the PDF for better navigation.
func DrawGrid(pdf *gofpdf.Fpdf) {
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
