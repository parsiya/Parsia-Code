package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

// If true, game will be played in the command line.
var cli bool

// If provided, it will point to the home key.
var home string

// If provided, points to the book file, otherwise gopher.json will be used.
var bookFile string

// Port used by the webserver.
var port int

func init() {
	flag.BoolVar(&cli, "cli", false, "start the game in the command line")
	flag.StringVar(&home, "home", "intro", "designate the starting page")
	flag.StringVar(&bookFile, "book", "gopher.json", "json file containing the book")
	flag.IntVar(&port, "port", 1234, "web server port")
	flag.Parse()
}

func main() {

	if port <= 0 || port > 65535 {
		panic(fmt.Errorf("wrong port: %v", port))
	}

	f, err := os.Open(bookFile)
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

	var currentPage string
	if cli {
		var c cliHandler
		if err := c.Init(cliTemplate, book, home); err != nil {
			panic(err)
		}
		fmt.Println("Let's start the game.")
		currentPage = home

		// While we have not reached and ending.
		for !c.IsEnding(currentPage) {
			fmt.Println(c.ExecuteTemplate(currentPage))
			var choice string
			fmt.Scanln(&choice)
			if c.HasOption(currentPage, choice) {
				currentPage = choice
				continue
			}
			fmt.Println("Wrong choice.")
			continue
		}

		fmt.Println(c.ExecuteTemplate(currentPage))
		fmt.Println("Thanks for playing, press any key to quit.")
		fmt.Scanln()

	} else {
		var wb webHandler
		if err := wb.Init(webTemplate, book, home); err != nil {
			panic(err)
		}
		addr := fmt.Sprintf("localhost:%d", port)
		fmt.Println("Starting adventure server at", addr)
		err := http.ListenAndServe(addr, wb)
		if err != nil {
			panic(err)
		}
	}
}
