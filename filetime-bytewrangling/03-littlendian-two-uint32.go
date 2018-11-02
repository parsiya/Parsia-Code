package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

func main() {
	// Simulate 8 bytes BigEndian.
	cr, _ := hex.DecodeString(strings.Replace("D0 E9 EE F2 15 15 C9 01", " ", "", -1))
	// Create an io.Reader from []byte.
	buf := bytes.NewReader(cr)
	var u32One, u32Two uint32
	err := binary.Read(buf, binary.LittleEndian, &u32One)
	if err != nil {
		panic(err)
	}
	err = binary.Read(buf, binary.LittleEndian, &u32Two)
	if err != nil {
		panic(err)
	}

	fmt.Printf("u32-1: %08x\n", u32One) // u32-1: f2eee9d0
	fmt.Printf("u32-1: %08x\n", u32Two) // u32-1: 01c91515
}
