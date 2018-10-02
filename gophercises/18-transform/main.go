package main

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/parsiya/Parsia-Code/gophercises/18-transform/primitive"
)

func main() {

	// Start a new web server.
	mux := http.NewServeMux()
	// Return the form.
	mux.HandleFunc("/", transformHandler)
	mux.HandleFunc("/upload", uploadHandler)
	fmt.Println("server running at localhost:8080")

	// Create a file server to serve files.
	myFileServer := http.FileServer(http.Dir("./img/"))
	// According to the video, fileServer expects the path to be relative to the root,
	// so if we go to /img/whatever.png, it's looking for /img/img/whatever.png.
	// So we strip /img from the start with http.StripPrefix.
	mux.Handle("/img/", http.StripPrefix("/img", myFileServer))

	http.ListenAndServe("localhost:8080", mux)

	// f, err := os.Open("img/img2.jpg")
	// if err != nil {
	// 	panic(err)
	// }
	// defer f.Close()

	// r, err := primitive.Transform(f, "jpg", 100, primitive.Combo)
	// if err != nil {
	// 	panic(err)
	// }

	// f2, err := os.Create("img/img2-out.jpg")
	// if err != nil {
	// 	panic(err)
	// }
	// defer f2.Close()
	// io.Copy(f2, r)
}

// --------

// transformHandler displays the HTML form used to upload the image.
func transformHandler(w http.ResponseWriter, r *http.Request) {
	// Form upload HTML.
	// https://developer.mozilla.org/en-US/docs/Web/HTML/Element/input/file
	formHTML := `
	<html><body>
		<form action="/upload" method="post" enctype="multipart/form-data">
			Choose file: <input type="file"
				id="upload" name="upload"
				accept="image/jpeg,image/png" />
			<br>
			<br>
			Number of shapes: <input type="text" value="0" name="numberOfShapes">
			<br>
			<br>
			Mode:
			<select name="mode">
				{{ range $i, $v := . }}
					<option value="{{ $i }}">{{ $v }}</option>
				{{ end }}
			</select>
			  </br>
			<button type="submit">Upload Image</button>
		</form>
	</body></html>`
	// We learned about templates in Hugo and lesson 03.
	tpl, err := template.New("upload form").Parse(formHTML)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Join all primitive modes.
	modes := []string{
		"Combo", "Triangle", "Rect", "Ellipse", "Circle", "RotatedRect",
		"Beziers", "RotatedEllipse", "Polygon",
	}

	if err := tpl.Execute(w, modes); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
}

// uploadHandler processes the uploaded file.
func uploadHandler(w http.ResponseWriter, r *http.Request) {

	// Get the file
	fi, he, err := r.FormFile("upload")
	if err != nil {
		// Return 400.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// From "link (?)" lesson remember it contains the period. E.g. ".jpg" ".png"
	extension := filepath.Ext(he.Filename)

	// Get other parameters.
	params := r.PostForm
	numberOfShapes, err := strconv.Atoi(params["numberOfShapes"][0])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if numberOfShapes == 0 {
		numberOfShapes = 30
	}

	mode, err := strconv.Atoi(params["mode"][0])
	if err != nil {
		mode = 0
	}

	// Transform the file.
	re, err := primitive.Transform(fi, extension, numberOfShapes, primitive.PrimitiveMode(mode))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Create a writer for the file.
	out, err := os.Create("img/transformed_" + he.Filename)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer out.Close()

	// Create a multiwriter to write both to the file and response.
	mw := io.MultiWriter(out, w)

	// Set the content-type for the response.
	w.Header().Set("Content-Type", "image/"+extension[1:])
	io.Copy(mw, re)
}
