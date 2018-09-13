package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"os"
)

var depth int
var start string
var fileName string
var logEnabled bool
var myLog *log.Logger

func init() {

	flag.IntVar(&depth, "depth", math.MaxInt32, "specify sitemap depth")
	flag.StringVar(&start, "url", "", "staring URL - must be provided")
	flag.StringVar(&fileName, "file", "", "name of xml file")
	flag.BoolVar(&logEnabled, "log", false, "display logs")
	flag.Parse()

}

func main() {

	if logEnabled {
		myLog = log.New(os.Stdout, "", log.Ltime)
	} else {
		myLog = log.New(ioutil.Discard, "", log.Ltime)
	}

	if start == "" {
		fmt.Printf("Starting URL must be provided - input was empty")
		return
	}

	myLog.Println("Starting URL:", start)
	myLog.Println("Depth:", depth)

	var m mapper
	if err := m.Init(start, depth); err != nil {
		myLog.Println(err.Error())
		myLog.Println("Error initializing the mapper, aborting")
		return
	}

	myLog.Println("Start processing.")
	m.Process()
	myLog.Println("Finished processing.")

	xmlFile := urlset{Xmlns: "http://www.sitemaps.org/schemas/sitemap/0.9"}

	for el := range m.Visited {
		xmlFile.Urls = append(xmlFile.Urls, xmlLink{URL: el.String()})
	}

	mw := []io.Writer{os.Stdout}
	if fileName != "" {
		f, err := os.Create(fileName)
		if err != nil {
			myLog.Printf("cannot open target file: %v\n", err)
		} else {
			mw = append(mw, f)
		}
		defer f.Close()
	}

	xmlEncoder := xml.NewEncoder(io.MultiWriter(mw...))
	xmlEncoder.Indent("", "  ")
	if err := xmlEncoder.Encode(xmlFile); err != nil {
		myLog.Printf("error encoding the xml: %v\n", err)
		return
	}
	fmt.Println()
	myLog.Println("Done")
}
