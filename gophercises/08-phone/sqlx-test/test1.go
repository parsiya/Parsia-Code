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
	db, err = sqlx.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err)
	}

	fmt.Printf("%+v\n", db)

	// force a connection and test that it worked
	err = db.Ping()
	if err != nil {
		panic(err)
	}

	fmt.Print("Finished pinging.")

	db.Close()
}
