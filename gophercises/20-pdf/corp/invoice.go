// Contains the invoice struct and methods.
package corp

import (
	"fmt"
	"strconv"
)

// Invoice contains the information for one invoice.
type Invoice struct {
	ClientName, ClientAddress, InvoiceNumber, Date string
	Items                                          []Item
	Total                                          float64
}

// Item represents one item in the invoice.
type Item struct {
	Description  string
	PricePerUnit float64
	Quantity     float64
}

// CalcTotal updates the invoice total.
func (i *Invoice) CalcTotal() {
	var total float64
	for _, item := range i.Items {
		total += item.PricePerUnit * item.Quantity
	}
	i.Total = total
}

// AddItem, adds an item to the invoice and recalculates the total.
func (i *Invoice) AddItem(item Item) error {
	// Check if item is populated.
	// Instead of an extra OR, we check if either price or quantity is empty.
	if item.Description == "" || item.PricePerUnit*item.PricePerUnit == 0 {
		return fmt.Errorf("corp.AddItem: empty item")
	}
	i.Items = append(i.Items, item)
	i.CalcTotal()
	return nil
}

// FloatToDollar converts a float to a string with only 2 floating points.
func FloatToDollar(f float64) string {
	return "$" + strconv.FormatFloat(f, 'f', 2, 64)
}

// FloatToText converts a float to string and drops any floating points.
func FloatToText(f float64) string {
	return strconv.FormatFloat(f, 'f', 0, 64)
}
