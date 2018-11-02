package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"syscall"
	"time"
)

func main() {
	cr, _ := hex.DecodeString(strings.Replace("D0 E9 EE F2 15 15 C9 01", " ", "", -1))
	buf := bytes.NewReader(cr)
	var timestamp [8]byte
	err := binary.Read(buf, binary.LittleEndian, &timestamp)
	if err != nil {
		panic(err)
	}

	t := toTime(timestamp)
	fmt.Println(t)
	fmt.Println(t.UTC())
}

// toTime converts an 8-byte Windows Filetime to time.Time.
func toTime(t [8]byte) time.Time {
	ft := &syscall.Filetime{
		LowDateTime:  binary.LittleEndian.Uint32(t[:4]),
		HighDateTime: binary.LittleEndian.Uint32(t[4:]),
	}
	return time.Unix(0, ft.Nanoseconds())
}
