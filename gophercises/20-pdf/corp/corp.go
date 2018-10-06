// Package corp is used to create the company's invoice in PDF format.
package corp

import (
	"fmt"
	"reflect"
	"strconv"

	"github.com/jung-kurt/gofpdf"
)

// Company represents a company.
// Every company has a logo path, contact info, and address.
type Company struct {
	Logo, ContactInfo, Address string
}

// SetHeader, creates the header for the invoice.
func (c Company) SetHeader(pdf *gofpdf.Fpdf) error {

	// Iterate through values and check if they are set.
	// Don't use reflection at home kids.
	v := reflect.ValueOf(c)
	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).Interface() == "" {
			return fmt.Errorf("Corp not initialized. Set value of %s", v.Type().Field(i).Name)
		}
	}
	// Set the header.
	pdf.SetHeaderFunc(func() {
		w, _ := pdf.GetPageSize()

		// Set the color (use the color from the example).
		pdf.SetFillColor(bannerR, bannerG, bannerB)

		bannerPoints := []gofpdf.PointType{
			{0, 0},                         // Start at top-left.
			{w, 0},                         // Go to top-right.
			{w, bannerHeight},              // Go down to banner height.
			{0, bannerHeight * bannerSkew}, // Go left and a bit up.
		}

		// Just fill it.
		pdf.Polygon(bannerPoints, "F")

		// Type INVOICE at 50, 60
		pdf.SetFont("courier", "B", bannerInvoiceFontSize)
		pdf.SetTextColor(headerR, headerG, headerB)
		pdf.Text(bannerInvoiceX, bannerInvoiceY, invoiceTitleText)

		// Add logo. Not using the original picture because I am not sure
		// about the license. Just gonna grab something in the public domain from
		// the internet.
		// Logo will be set at 281, 20
		logoOpts := gofpdf.ImageOptions{
			ReadDpi: true,
		}
		pdf.ImageOptions(c.Logo, bannerLogoX, bannerLogoY, logoWidth, logoHeight, false, logoOpts, 0, "")

		// So we will use normal text and split on new lines.
		// TextCell with contact info.
		pdf.MoveTo(bannerContactX, bannerContactY)
		pdf.SetFont("courier", "B", 12)
		_, lpt := pdf.GetFontSize()
		pdf.SetTextColor(headerR, headerG, headerB)
		pdf.MultiCell(bannerContactCellWidth, lpt, c.ContactInfo, "0", "LT", false)

		// MultiCell with address.
		pdf.MoveTo(bannerAddressX, bannerAddressY)
		pdf.MultiCell(bannerCellWidth, lpt, c.Address, "0", "RT", false)
	})
	return nil
}

// SetFooter sets the simple footer.
func (c Company) SetFooter(pdf *gofpdf.Fpdf) {
	pdf.SetFooterFunc(func() {
		w, h := pdf.GetPageSize()

		// Draw the footer polygon.
		footerPoints := []gofpdf.PointType{
			{0, h},
			{0, h - footerHeight},
			{w, h - (footerHeight * footerSkew)},
			{w, h},
		}
		pdf.SetFillColor(bannerR, bannerG, bannerB)
		pdf.Polygon(footerPoints, "F")
	})
}

// InvoiceHeader renders the top part of the invoice with client name, client
// address, invoice number, date of issue, and the huge invoice total.
func (c Company) InvoiceHeader(pdf *gofpdf.Fpdf, invoice Invoice) error {

	// Check if invoice is empty.
	if len(invoice.Items) == 0 {
		return fmt.Errorf("corp.InvoiceHeader: empty invoice")
	}

	w, _ := pdf.GetPageSize()
	pdf.SetFont("Times", "B", 12)
	_, lpt := pdf.GetFontSize()

	// Render "Billed To"
	pdf.SetTextColor(greyRGB, greyRGB, greyRGB)
	pdf.MoveTo(xIndent, headerStartY)
	pdf.Write(lpt, billedToText)

	// Go 2*lpt down and render client name
	_, curY := pdf.GetXY()
	pdf.MoveTo(xIndent, curY+(2*lpt))
	pdf.SetTextColor(mainR, mainG, mainB)
	pdf.Write(lpt, invoice.ClientName)

	// Go 1.5*lpt down and render client address in a multicell.
	_, curY = pdf.GetXY()
	pdf.MoveTo(xIndent, curY+(1.5*lpt))
	pdf.MultiCell(200, lpt, invoice.ClientAddress, "0", "TL", false)

	// Render "Invoice Number".
	pdf.SetTextColor(greyRGB, greyRGB, greyRGB)
	pdf.MoveTo(headerMiddleX, headerStartY)
	pdf.Write(lpt, invoiceNumberText)

	// Go 1.5*lpt down and render invoice number.
	pdf.SetTextColor(mainR, mainG, mainB)
	_, curY = pdf.GetXY()
	pdf.MoveTo(headerMiddleX, curY+(1.5*lpt))
	pdf.Write(lpt, invoice.InvoiceNumber)

	// Go 2*lpt down and render "Date of Issue".
	pdf.SetTextColor(greyRGB, greyRGB, greyRGB)
	_, curY = pdf.GetXY()
	pdf.MoveTo(headerMiddleX, curY+(2*lpt))
	pdf.Write(lpt, dateOfIssueText)

	// Go 1.5*lpt down and render date of issue.
	pdf.SetTextColor(mainR, mainG, mainB)
	_, curY = pdf.GetXY()
	pdf.MoveTo(headerMiddleX, curY+(1.5*lpt))
	pdf.Write(lpt, invoice.Date)

	// Render "Invoice Total"
	pdf.SetTextColor(greyRGB, greyRGB, greyRGB)
	pdf.MoveTo(w-xIndent, headerStartY-lpt)
	// WriteAligned will help us write this text. If first param is 0, all page
	// is considered.
	pdf.WriteAligned(0, lpt, invoiceTotalText, "R")

	// Render invoice total in big letters.
	pdf.SetTextColor(bannerR, bannerG, bannerB)
	pdf.SetFont("Times", "B", 40)
	_, lptBig := pdf.GetFontSize()
	pdf.MoveTo(w-xIndent, headerStartY+lptBig)
	pdf.WriteAligned(0, 0, FloatToDollar(invoice.Total), "R")

	// Draw the line after header with a filled rectangle.
	pdf.SetFillColor(bannerR, bannerG, bannerB)
	pdf.Rect(xIndent*0.5, headerEndY, w-xIndent, headerLineThickness, "F")

	return nil
}

// ItemList renders the item list in the invoice.
func (c Company) ItemList(pdf *gofpdf.Fpdf, invoice Invoice) error {

	// Check if invoice is empty.
	if len(invoice.Items) == 0 {
		return fmt.Errorf("corp.InvoiceHeader: empty invoice")
	}

	w, _ := pdf.GetPageSize()
	pdf.SetFont("Times", "B", 12)
	_, lpt := pdf.GetFontSize()

	// Write "Description"
	pdf.MoveTo(itemList1stColumnX, itemListTopY)
	pdf.SetTextColor(greyRGB, greyRGB, greyRGB)
	pdf.Write(lpt, descriptionText)

	// Write "Price Per Unit"
	pdf.MoveTo(itemList2ndColumnX, itemListTopY)
	pdf.WriteAligned(100, lpt, pricePerUnitText, "R")

	// Write "Quantity"
	pdf.MoveTo(itemList3rdColumnX, itemListTopY)
	pdf.WriteAligned(100, lpt, quantityText, "R")

	// Write "Amount"
	pdf.SetTextColor(0, 0, 0)
	pdf.MoveTo(itemList4thColumnX, itemListTopY)
	pdf.Write(lpt, amountText)

	// ***** Start items *****
	pdf.SetTextColor(0, 0, 0) // Redundant but useful in case we change colors later.
	for i, item := range invoice.Items {
		itemY := float64(i+1)*4*lpt + itemListTopY
		// Write description.
		pdf.MoveTo(itemList1stColumnX, itemY-lpt)
		// pdf.Write(lpt, item.Description)
		pdf.MultiCell(200, lpt, item.Description, "0", "TL", false)

		// Write price per unit.
		pdf.MoveTo(itemList2ndColumnX, itemY)
		pdf.WriteAligned(100, lpt, FloatToDollar(item.PricePerUnit), "R")
		// Write quantity.
		pdf.MoveTo(itemList3rdColumnX, itemY)
		pdf.WriteAligned(100, lpt, FloatToText(item.Quantity), "R")
		// Write total amount.
		pdf.MoveTo(itemList4thColumnX, itemY)
		pdf.Write(lpt, FloatToDollar(item.Quantity*item.PricePerUnit))

		// Draw the grey line after each item.
		lineY := itemY + 2*lpt
		pdf.SetFillColor(greyRGB, greyRGB, greyRGB)
		pdf.Rect(xIndent*0.5, lineY, w-xIndent, itemListLineThickness, "F")
	}

	// Draw "Subtotal"
	curY := pdf.GetY()
	pdf.MoveTo(itemList2ndColumnX, curY+4*lpt)
	pdf.SetTextColor(greyRGB, greyRGB, greyRGB)
	pdf.Write(lpt, subtotalText)

	pdf.MoveTo(itemList4thColumnX, curY+4*lpt)
	pdf.SetTextColor(0, 0, 0)
	pdf.Write(lpt, FloatToDollar(invoice.Total))

	return nil
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
