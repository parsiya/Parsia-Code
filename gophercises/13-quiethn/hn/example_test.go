// The client tests need to be inside the hn package so this test file
// was created for examples that use the hn package from an external package
// like a normal user would.
package hn_test

import (
	"fmt"

	"github.com/gophercises/quiet_hn/hn"
)

func ExampleClient() {
	var client hn.Client
	ids, err := client.TopItems()
	if err != nil {
		panic(err)
	}
	for i := 0; i < 5; i++ {
		item, err := client.GetItem(ids[i])
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s (by %s)\n", item.Title, item.By)
	}
}
