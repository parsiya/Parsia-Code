package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

func main() {
	// Simulate 8 bytes BigEndian.
	cr, _ := hex.DecodeString(strings.Replace("D0 E9 EE F2 15 15 C9 01", " ", "", -1))
	// Read them into a uint64
	u64 := binary.LittleEndian.Uint64(cr)
	// Print the bytes
	fmt.Printf("%016x", u64)
	// 01c91515f2eee9d0
}
