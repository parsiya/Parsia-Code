package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func main() {

	f, err := os.Open("gopher.json")
	if err != nil {
		panic(err)
	}

	jsonBytes, err := ioutil.ReadAll(f)
	if err != nil {
		panic(err)
	}

	book := make(map[string]Page)

	if err := json.Unmarshal(jsonBytes, &book); err != nil {
		panic(err)
	}

	var h myHandler
	if err := h.Init(webTemplate, book); err != nil {
		panic(err)
	}
	fmt.Println("Starting adventure server on port 1234")
	http.ListenAndServe("localhost:1234", h)
}
