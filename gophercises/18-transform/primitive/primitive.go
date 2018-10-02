package primitive

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

type PrimitiveMode int

const (
	Combo PrimitiveMode = iota
	Triangle
	Rect
	Ellipse
	Circle
	RotatedRect
	Beziers
	RotatedEllipse
	Polygon
)

// primCLI runs primitive on the command line.
// primitive -i input.png -o output.png -n 100 -m 1
func primCLI(in, out string, numberOfShapes int, mode PrimitiveMode) (string, error) {

	args := fmt.Sprintf("-i %s -o %s -n %d -m %d", in, out, numberOfShapes, mode)
	fmt.Println("Running primitive", args)
	cmd := exec.Command("primitive", strings.Fields(args)...)
	fmt.Println("Finished running primitive CLI")
	b, err := cmd.CombinedOutput()
	return string(b), err
}

// Transform runs the image through primitive with options.
func Transform(imgFile io.Reader, extension string, numberOfShapes int, mode PrimitiveMode) (io.Reader, error) {

	// Create temp input file.
	inputName := "tempinput" + extension
	i, err := os.Create(inputName)
	if err != nil {
		return nil, fmt.Errorf("primitive.Transform: cannot create temp input - %v", err)
	}

	// Remember defer is a stack so close needs to happen before remove.
	defer os.Remove(inputName)
	defer i.Close()

	// Write imgFile into a tempfile.
	_, err = io.Copy(i, imgFile)
	if err != nil {
		return nil, fmt.Errorf("primitive.Transform: cannot populate input file - %v", err)
	}

	outputName := "tempoutput" + extension

	runOutput, err := primCLI(inputName, outputName, numberOfShapes, mode)
	if err != nil {
		return nil, fmt.Errorf("primitive.Transform: error running primitive command - %v\nOutput: %s", err, runOutput)
	}

	// Open output file.
	o, err := os.Open(outputName)
	if err != nil {
		return nil, fmt.Errorf("primitive.Transform: cannot open output file - %v", err)
	}

	// Read all of outputName to a buffer, create a reader and send it out.
	b, err := ioutil.ReadAll(o)
	if err != nil {
		return nil, fmt.Errorf("primitive.Transform: cannot read output file - %v", err)
	}
	defer os.Remove(outputName)
	defer o.Close()

	// Otherwise the files will not be deleted.
	r := bytes.NewReader(b)

	return r, nil
}
