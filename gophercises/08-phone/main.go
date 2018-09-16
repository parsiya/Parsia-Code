package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

var (
	phoneFile string
	dbFile    string
)

func init() {
	flag.StringVar(&phoneFile, "ph", "phones.txt", "file with original phone numbers")
	flag.StringVar(&dbFile, "db", "phones.db", "database file")
	flag.Parse()
}

func main() {

	var phones []string
	// Read the phone numbers from phones.txt.
	phoneFile, err := os.Open(phoneFile)
	if err != nil {
		panic(err)
	}
	// Read line by line using bufio.Scanner.
	scanner := bufio.NewScanner(phoneFile)
	for scanner.Scan() {
		phones = append(phones, scanner.Text())
	}
	if err = scanner.Err(); err != nil {
		fmt.Fprintln(os.Stdout, "reading from file:", err)
	}

	// Delete the database file.
	if err = os.Remove(dbFile); err != nil {
		fmt.Println(err)
	}

	// Open the database (which creates the file because it was deleted).
	var db *sqlx.DB

	db, err = sqlx.Connect("sqlite3", dbFile)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	fmt.Println("Creating phone_numbers.")
	// Create the table from scratch.
	createTable := "CREATE TABLE phone_numbers(phone text);"
	_, err = db.Exec(createTable)
	// Returns an error if table already exists.
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("Adding phone numbers to the table.")
	// Add all phones to the phone_numbers table.
	addPhone := "INSERT INTO phone_numbers(phone) VALUES (?);"
	for _, p := range phones {
		if _, err = db.Exec(addPhone, p); err != nil {
			fmt.Println(err)
		}
	}

	// Now all phones are in the table.

	// 1. Read all phones from the table.
	// 2. Normalize them.
	// 3. Add normalized values to a map.

	// We could use map[string]struct{} to save a few bytes.
	uniques := make(map[string]bool)

	fmt.Println("Reading from phone_numbers.")
	listPhones := "SELECT * FROM phone_numbers;"
	rows, err := db.Query(listPhones)
	if err != nil {
		panic(err)
	}
	for rows.Next() {
		var number string
		err = rows.Scan(&number)
		if err != nil {
			fmt.Println(err)
		}
		uniques[normalize(number)] = true
	}

	// Unique phone numbers are now in uniques.

	fmt.Println("Creating unique_numbers.")
	// Create new table named unique_numbers.
	uniqueTable := "CREATE TABLE unique_numbers(phone text);"
	_, err = db.Exec(uniqueTable)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("Adding unique phone numbers to unique_numbers.")
	addUnique := "INSERT INTO unique_numbers(phone) VALUES (?);"
	for k := range uniques {
		if _, err = db.Exec(addUnique, k); err != nil {
			fmt.Println(err)
		}
	}

	fmt.Println("Reading unique phone numbers from unique_numbers.")
	listUniques := "SELECT * FROM unique_numbers;"
	rows, err = db.Query(listUniques)
	if err != nil {
		panic(err)
	}
	for rows.Next() {
		var number string
		err = rows.Scan(&number)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(number)
	}
}

// normalize, removes all non-digits from the phone number.
func normalize(n string) string {
	var out bytes.Buffer
	// Iterate through runes. Down with regex.
	for _, ch := range n {
		if '9' >= ch && ch >= '0' {
			out.WriteRune(ch)
		}
	}
	return out.String()
}
