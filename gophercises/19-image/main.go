package main

import "fmt"

func main() {

	// Recreate the bar chart with svgo.
	if err := drawSVG("img.svg", []int{10, 33, 73, 64}); err != nil {
		fmt.Println("error when calling drawSVG", err)
	}

	// Create usage data
	usageData := []Usage{
		{"Jan", 171},
		{"Feb", 180},
		{"Mar", 100},
		{"Apr", 87},
		{"May", 66},
		{"Jun", 40},
		{"Jul", 32},
		{"Aug", 55},
	}

	if err := usageSVG("usage.svg", usageData); err != nil {
		fmt.Println("error when calling usageSVG", err)
	}
}
