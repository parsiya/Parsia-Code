# Gophercises - 7 - CLI Task Manager

## Problem

* https://github.com/gophercises/task
* https://gophercises.com/exercises/task


## Solution

* I went directly for bonus, minus the home directory part. See examples further down:

  ```
  $ go run main.go database.go --help
  NAME:
  task - task is a CLI for managing your TODOs.

  USAGE:
  main.exe [global options] command [command options] [arguments...]

  COMMANDS:
      add, a              Add a new task to your TODO list.
      do, d               Mark a task on your TODO list as complete.
      list, l             List all incomplete tasks.
      completed, c, done  List all completed tasks.
      rm, r               Remove and incomplete task from list.
      help, h             Shows a list of commands or help for one command

  GLOBAL OPTIONS:
  --help, -h  show help
  ```

## Lessons Learned

### urfave/cli Package

* godoc: [https://godoc.org/github.com/urfave/cli](https://godoc.org/github.com/urfave/cli)

Examples:

* http://securitygobyexample.com/urfave-cli-subcommands
* http://securitygobyexample.com/urfave-cli-flags

### BoltDB

* https://github.com/boltdb/bolt
    * Repository's README is a good guide to get started.
* Key/Value store.
* Create buckets first.
* At the start of each transaction you need to get the buckets.
* In general, values do not transfer between transactions. If you want do, you need to `Copy` slice of results to another variable to use it outside.
* See short example in [bolt-test/main.go](bolt-test/main.go).

### Using Time as Keys in BoltDB for Indexing
Read this:

* Source: https://zupzup.org/boltdb-example/
* Code: https://github.com/zupzup/boltdb-example

``` go
key := []byte(time.Now().Format(time.RFC3339))
```

And later we can search with `seek`.

### time.Add vs. time.Sub

* `time.Add` gets a `time.Duration` and returns `time.Time`:
    * `func (t Time) Add(d Duration) Time`
    * https://golang.org/pkg/time/#Time.Add
* `time.Sub` gets a `time.Time` and returns `time.Duration`:
    * `func (t Time) Sub(u Time) Duration`
    * https://golang.org/pkg/time/#Time.Sub

Obviously both support negative values.

### Convert int Variable to time.Duration
You can multiple `time.Duration` by a constant (e.g. `time.Hours * 2`) but cannot multiply it by an `int` variable with value of 2 (e.g. `time.Hours * n`).

`n` needs to be converted to `in64` and then passed to `time.Duration(int64)`. For example, to go back `n` hours:

``` go
past := time.Now().Add(-time.Duration(int64(n)) * time.Hour)
```

### Seek in Bucket

``` go
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
```

## Sample Usage

Add tasks:

```
$ go run main.go database.go add "task 1"
Added "task 1" to your task list.
Listing all tasks:

+--------+---------------------------+--------+
| NUMBER |        TIME ADDED         |  TASK  |
+--------+---------------------------+--------+
|      1 | 2018-09-15T15:57:13-05:00 | task 1 |
+--------+---------------------------+--------+

$ go run main.go database.go add "task 2"
Added "task 2" to your task list.
Listing all tasks:

+--------+---------------------------+--------+
| NUMBER |        TIME ADDED         |  TASK  |
+--------+---------------------------+--------+
|      1 | 2018-09-15T15:57:13-05:00 | task 1 |
|      2 | 2018-09-15T15:57:22-05:00 | task 2 |
+--------+---------------------------+--------+
```

List tasks:

```
$ go run main.go database.go list
Listing all tasks:

+--------+---------------------------+--------+
| NUMBER |        TIME ADDED         |  TASK  |
+--------+---------------------------+--------+
|      1 | 2018-09-15T15:57:13-05:00 | task 1 |
|      2 | 2018-09-15T15:57:22-05:00 | task 2 |
+--------+---------------------------+--------+
```

Complete task:

```
$ go run main.go database.go do 2
You have completed the "task 2" task.
Listing all tasks:

+--------+---------------------------+--------+
| NUMBER |        TIME ADDED         |  TASK  |
+--------+---------------------------+--------+
|      1 | 2018-09-15T15:57:13-05:00 | task 1 |
+--------+---------------------------+--------+
```

If index is out of range, you get an error:

```
$ go run main.go database.go do 3
Listing all tasks:

+--------+---------------------------+--------+
| NUMBER |        TIME ADDED         |  TASK  |
+--------+---------------------------+--------+
|      1 | 2018-09-15T15:57:13-05:00 | task 1 |
+--------+---------------------------+--------+
Invalid index entered: 3
Index should be in range of 1 to 1.
exit status 3
```

If list is empty, you are asked to add more tasks:

```
$ go run main.go database.go do 1
You have completed the "task 1" task.

$ go run main.go database.go do 3
Task list is empty, add some tasks first.
exit status 3
```

List completed tasks in the last n hours (default is 24):

```
$ go run main.go database.go done

You have finished the following tasks in the last 24 hour(s):
+--------+---------------------------+--------+
| NUMBER |      TIME COMPLETED       |  TASK  |
+--------+---------------------------+--------+
|      1 | 2018-09-15T16:04:05-05:00 | task 2 |
|      2 | 2018-09-15T16:05:00-05:00 | task 1 |
+--------+---------------------------+--------+
```

You can also list tasks completed in the last n hours:

```
$ go run main.go database.go done 3

You have finished the following tasks in the last 3 hour(s):
+--------+---------------------------+--------+
| NUMBER |      TIME COMPLETED       |  TASK  |
+--------+---------------------------+--------+
|      1 | 2018-09-15T16:04:05-05:00 | task 2 |
|      2 | 2018-09-15T16:05:00-05:00 | task 1 |
+--------+---------------------------+--------+
```

Remove uncomplete tasks:

```
>go run main.go database.go list
Listing all tasks:

+--------+---------------------------+--------+
| NUMBER |        TIME ADDED         |  TASK  |
+--------+---------------------------+--------+
|      1 | 2018-09-15T16:06:04-05:00 | task 3 |
+--------+---------------------------+--------+

$ go run main.go database.go rm 1
You have deleted the "task 3" task.

$ go run main.go database.go list
List is empty.
exit status 3

$ go run main.go database.go done

You have finished the following tasks in the last 24 hour(s):
+--------+---------------------------+--------+
| NUMBER |      TIME COMPLETED       |  TASK  |
+--------+---------------------------+--------+
|      1 | 2018-09-15T16:04:05-05:00 | task 2 |
|      2 | 2018-09-15T16:05:00-05:00 | task 1 |
+--------+---------------------------+--------+
```