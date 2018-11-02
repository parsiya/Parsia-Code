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
	// Create an io.Reader from []byte for simulation.
	buf := bytes.NewReader(cr)
	var u64 uint64
	err := binary.Read(buf, binary.LittleEndian, &u64)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%016x", u64)
	// 01c91515f2eee9d0
}
