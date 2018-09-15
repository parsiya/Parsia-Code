// Database methods and utils.

package main

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/boltdb/bolt"
)

// Task represents a task when extracted from the database.
type Task struct {
	Key  string `json:"key"`
	Text string `json:"text"`
}

// ********************

// Database represents a task database.
type Database struct {
	db         *bolt.DB
	file       string // Filename for the database.
	bucketOpen []byte // Open tasks bucket name.
	bucketDone []byte // Compleed tasks bucket name.
}

// NewDB creates a new DB and returns a pointer.
func NewDB(file string, open []byte, done []byte) (*Database, error) {
	db, err := bolt.Open(file, os.ModeExclusive, bolt.DefaultOptions)
	if err != nil {
		return nil, err
	}

	// Create the buckets if they do not exist.
	if err = db.Update(func(tx *bolt.Tx) error {
		_, errBucket := tx.CreateBucketIfNotExists(open)
		if errBucket != nil {
			return fmt.Errorf("create bucket: %v", err)
		}
		_, errBucket = tx.CreateBucketIfNotExists(done)
		if errBucket != nil {
			return fmt.Errorf("create bucket: %v", err)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("create bucket: %v", err)
	}

	// Set database fields before returning.
	d := &Database{
		db:         db,
		bucketOpen: open,
		bucketDone: done,
		file:       file,
	}

	return d, nil
}

// Close closes the database handle.
func (d *Database) Close() error {
	return d.db.Close()
}

// AddTask adds a new task to the bucket.
// Checking if the task already exists is going to be painful so we won't do it.
func (d *Database) AddTask(task string, timestamp time.Time) error {
	err := d.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(d.bucketOpen)
		t := []byte(timestamp.Format(time.RFC3339))
		if putErr := b.Put(t, []byte(task)); putErr != nil {
			return fmt.Errorf("could not insert task :%v", putErr)
		}
		return nil
	})
	return err
}

// ListOpenTasks return all tasks in the openBucket.
func (d *Database) ListOpenTasks() []Task {

	var tasks []Task
	d.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(d.bucketOpen)
		b.ForEach(func(k, v []byte) error {
			tasks = append(tasks, Task{Key: string(k), Text: string(v)})
			return nil
		})
		return nil
	})
	return tasks
}

// DoTask completes a task. It is removed from the open bucket and moved to the done bucket.
func (d *Database) DoTask(key string, timestamp time.Time) error {
	err := d.db.Update(func(tx *bolt.Tx) error {
		bOpen := tx.Bucket(d.bucketOpen)
		taskText := bOpen.Get([]byte(key))
		if taskText == nil {
			return fmt.Errorf("key %v not found", key)
		}

		// Store it in the done bucket.
		bDone := tx.Bucket(d.bucketDone)
		t := []byte(timestamp.Format(time.RFC3339))
		if err := bDone.Put(t, taskText); err != nil {
			return fmt.Errorf("store key in done: %v", err)
		}

		// Delete it from the open bucket.
		if err := bOpen.Delete([]byte(key)); err != nil {
			return fmt.Errorf("delete key from open: %v", err)
		}

		// Return if everything worked.
		return nil
	})

	// Return error anyways. If transaction was successful, it's nil.
	// If not, it contains the error and we return it. Thanks linter :).
	return err
}

// ListCompletedTasks returns completed tasks (from the done bucket) with keys
// in the last n hours.
func (d *Database) ListCompletedTasks(n int) []Task {

	var tasks []Task

	// Go back n hours.
	past := time.Now().Add(-time.Duration(int64(n)) * time.Hour)
	// Convert it to key.
	pastKey := []byte(past.Format(time.RFC3339))

	nowKey := []byte(time.Now().Format(time.RFC3339))

	// Seek and add everything between past and now.
	d.db.View(func(tx *bolt.Tx) error {
		// Get a cursor to the bucket.
		done := tx.Bucket(d.bucketDone).Cursor()
		// Start seeking. If k (key) is nil, it means it does not exist so we skip it.
		for k, v := done.Seek(pastKey); k != nil && bytes.Compare(k, nowKey) <= 0; k, v = done.Next() {
			tasks = append(tasks, Task{Key: string(k), Text: string(v)})
		}
		return nil
	})
	return tasks
}

// DeleteTask removes an uncompleted a task. It is removed from the open bucket.
func (d *Database) DeleteTask(key string) error {
	err := d.db.Update(func(tx *bolt.Tx) error {
		// Check if it exists.
		bOpen := tx.Bucket(d.bucketOpen)
		taskText := bOpen.Get([]byte(key))
		if taskText == nil {
			return fmt.Errorf("key %v not found", key)
		}

		// Delete it from the open bucket.
		if err := bOpen.Delete([]byte(key)); err != nil {
			return fmt.Errorf("delete key from open: %v", err)
		}

		// Return if everything worked.
		return nil
	})

	// Return error anyways. If transaction was successful, it's nil.
	// If not, it contains the error and we return it. Thanks linter :).
	return err
}
