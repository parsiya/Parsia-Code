package main

import (
	"fmt"

	"github.com/parsiya/Parsia-Code/gophercises/09-deck/deck"
)

func main() {
	d := deck.NewDefault()
	fmt.Println(d)

	d1 := deck.New(deck.Shuffle(), deck.Sort())
	fmt.Println(d1)

	d2 := deck.New(deck.Multiply(2))
	fmt.Println(d2.Len())
}
