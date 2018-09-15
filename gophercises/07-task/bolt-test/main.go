package main

import (
	"fmt"
	"os"

	"github.com/boltdb/bolt"
)

// Learning BoltDB.

func main() {
	// Open DB
	db, err := bolt.Open("tasks.db", os.ModeExclusive, bolt.DefaultOptions)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	var b1, b2 *bolt.Bucket

	// Create buckets.
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("bucket1"))
		if err != nil {
			return fmt.Errorf("create bucket: %v", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte("bucket2"))
		if err != nil {
			return fmt.Errorf("create bucket: %v", err)
		}
		return nil
	}); err != nil {
		fmt.Println("error creating bucket")
		panic(err)
	}

	// Write some stuff into buckets.
	if err := db.Update(func(tx *bolt.Tx) error {
		b1 = tx.Bucket([]byte("bucket1"))
		b2 = tx.Bucket([]byte("bucket2"))

		if err := b1.Put([]byte("key1"), []byte("value1")); err != nil {
			return err
		}

		if err := b2.Put([]byte("key2"), []byte("value2")); err != nil {
			return err
		}
		return nil
	}); err != nil {
		fmt.Println("error doing update")
		panic(err)
	}

	if err := db.View(func(tx *bolt.Tx) error {
		b1 = tx.Bucket([]byte("bucket1"))
		b2 = tx.Bucket([]byte("bucket2"))

		val1 := b1.Get([]byte("key1"))
		fmt.Printf("%s\n", val1)
		val2 := b2.Get([]byte("key2"))
		fmt.Printf("%s\n", val2)
		return nil
	}); err != nil {
		fmt.Println("error doing view")
		panic(err)
	}

}
