package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

func main() {
	cr, _ := hex.DecodeString("4C0000000114020000000000C000000000000046" +
		"9B00080020000000D0E9EEF21515C901D0E9EEF21515C901D0E9EEF21515C90100" +
		"0000000000000001000000000000000000000000000000")
	// Create an io.Reader from []byte.
	buf := bytes.NewReader(cr)

	headerLittleEndian := make([]byte, 72)
	err := binary.Read(buf, binary.LittleEndian, &headerLittleEndian)
	if err != nil {
		panic(err)
	}
	fmt.Println("headerLittleEndian")
	fmt.Println(hex.Dump(headerLittleEndian))

	// Reset the reader.
	buf = bytes.NewReader(cr)
	headerBigEndian := make([]byte, 72)
	err = binary.Read(buf, binary.BigEndian, &headerBigEndian)
	if err != nil {
		panic(err)
	}
	fmt.Println("headerBigEndian")
	fmt.Println(hex.Dump(headerBigEndian))
}
