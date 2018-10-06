// Contains constants for the package.
package corp

const (
	// Page constants
	bannerHeight = 100.0
	bannerSkew   = 0.9
	xIndent      = 40.0
	footerHeight = 40.0
	footerSkew   = 0.8

	// ***** Banner *****
	// Banner color.
	bannerR = 103
	bannerG = 60
	bannerB = 79

	// INVOICE Location
	bannerInvoiceX = 50
	bannerInvoiceY = 60
	// Size of INVOICE
	bannerInvoiceFontSize = 40

	// Logo Location
	bannerLogoX = 281
	bannerLogoY = 20
	// Logo size
	logoWidth  = 50
	logoHeight = 50

	// Contact info location
	bannerContactX = 360
	bannerContactY = 30
	// Contact info cell width
	bannerContactCellWidth = 150

	// Address location
	bannerAddressX = 450
	bannerAddressY = 30
	// Banner cell width
	bannerCellWidth = 150

	// ***** Header *****
	// Where header text starts.
	headerStartY = 100
	// Where invoice number and date of issue are printed.
	headerMiddleX = 200
	// Where line after header is drawn.
	headerEndY = 200
	// Thickness of line after header
	headerLineThickness = 3.0

	// Grey color.
	greyRGB = 113

	// Header text color.
	headerR = 255
	headerG = 255
	headerB = 255

	// Main text color.
	mainR = 0
	mainG = 0
	mainB = 0

	// ***** Item list *****
	// Top of the item list - Description - Price per Unit etc.
	itemListTopY = 220
	// x of first column == xIndent
	itemList1stColumnX = xIndent
	// x of second column.
	itemList2ndColumnX = 300
	// x of third column.
	itemList3rdColumnX = 420
	// x of forth column.
	itemList4thColumnX = 500
	// Thickness of line after each item.
	itemListLineThickness = 1.0

	// Invoice text - this is useful in case we want to translate.
	invoiceTitleText  = "INVOICE"
	billedToText      = "Billed To"
	invoiceNumberText = "Invoice Number"
	dateOfIssueText   = "Date of Issue"
	invoiceTotalText  = "Invoice Total"
	descriptionText   = "Description"
	pricePerUnitText  = "Price Per Unit"
	quantityText      = "Quantity"
	amountText        = "Amount"
	subtotalText      = "Subtotal"
)
