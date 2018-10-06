package main

import (
	"fmt"

	"github.com/jung-kurt/gofpdf"
	"github.com/parsiya/Parsia-Code/gophercises/20-pdf/corp"
)

func main() {

	// Create a new corporation.
	co := corp.Company{
		Address: `123 Fake St.
		Some Town, PA
		12345`,
		ContactInfo: `(555)555-5555
		test@example.net
		example.net`,
		Logo: "img/logo.png",
	}

	// Create a new invoice.
	in := corp.Invoice{
		ClientName: "Client Name",
		ClientAddress: `1 Client Address
		City, State, Country
		Postal Code`,
		InvoiceNumber: "0000000123",
		Date:          "10/06/2018",
	}

	// Create items.
	it := []corp.Item{
		{
			"2x6 Lumber - 8'", 3.75, 220,
		},
		{
			"2x6 Lumber - 10'", 5.55, 18,
		},
		{
			"2x4 Lumber - 8'", 2.99, 80,
		},
		{
			"Drywall Sheet", 8.22, 50,
		},
		{
			"Paint", 14.55, 3,
		},
		{
			"Some item with a super long unit name to test our word wrapping",
			9.99, 22,
		},
	}

	// Add items to invoice.
	for _, i := range it {
		if err := in.AddItem(i); err != nil {
			panic(err)
		}
	}

	// Change papersize to letter because 'Murica is special!
	pdf := gofpdf.New(gofpdf.OrientationPortrait, gofpdf.UnitPoint, gofpdf.PageSizeLetter, "")

	// Set Header.
	if err := co.SetHeader(pdf); err != nil {
		panic(err)
	}
	co.SetFooter(pdf)

	pdf.AddPage()
	pdf.MoveTo(0, 0)

	// Draw invoice header.
	if err := co.InvoiceHeader(pdf, in); err != nil {
		panic(err)
	}

	// Draw item list.
	if err := co.ItemList(pdf, in); err != nil {
		panic(err)
	}

	// corp.DrawGrid(pdf)
	if err := pdf.OutputFileAndClose("invoice.pdf"); err != nil {
		panic(err)
	}
	fmt.Println("Done")
}
