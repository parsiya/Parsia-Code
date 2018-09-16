package main

import (
	"fmt"

	"github.com/jmoiron/sqlx"

	// Needed to make the driver work.
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	var db *sqlx.DB

	var err error

	// In memory sqlite3.
	// Can also use connect to open and connect at the same time.
	db, err = sqlx.Connect("sqlite3", "test2.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Create a simple table for phone numbers.
	table1 := `CREATE TABLE phones(
		phone text,
		description text,
		phoneID integer);`

	_, err = db.Exec(table1)
	// Returns an error if table already exists.
	if err != nil {
		fmt.Println(err)
	}

	// Add items to the phones table with bindvars.
	addPhone := `INSERT	INTO phones(phone, description, phoneID)
	VALUES (?, ?, ?);`

	// Now we can call it with values.
	_, err = db.Exec(addPhone, "555-555-5555", "phone1", 1)
	if err != nil {
		fmt.Println(err)
	}

	// With Query, we can run a select and get everything from phones.
	listPhones := `SELECT * FROM phones;`
	rows, err := db.Query(listPhones)
	if err != nil {
		fmt.Println(err)
	}

	// Iterate over rows.
	for rows.Next() {
		var ph string
		var de string
		var id int
		err = rows.Scan(&ph, &de, &id)
		if err != nil {
			fmt.Println(err)
		}
		// fmt.Println(ph, de, id)
	}

	// Can also iterate over structs with Queryx.
	// Struct fields must be exported, otherwise we get an error.
	// Use the tags to match table columns to fields if the names do not match.
	rowx, err := db.Queryx(listPhones)
	type phone struct {
		Phone string `db:"phone"`
		Desc  string `db:"description"`
		ID    int    `db:"phoneID"`
	}

	// Iterate over rows.
	for rowx.Next() {
		var p phone
		err = rowx.StructScan(&p)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Printf("%+v\n", p)
	}
}
