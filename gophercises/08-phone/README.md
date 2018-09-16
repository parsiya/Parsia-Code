# Gophercises - 8 - Phone Number Normalizer

## Problem

* https://github.com/gophercises/phone
* https://gophercises.com/exercises/phone


## Solution

* [main.go](main.go).
  ```
  $ go run main.go --help
    -db string
          database file (default "phones.db")
    -ph string
          file with original phone numbers (default "phones.txt")
  ```

You need to `go get`:

* https://github.com/jmoiron/sqlx
* https://github.com/mattn/go-sqlite3

`go-sqlite3` needs `cgo`. I had to install `MinGW-w64` on Windows:

* https://sourceforge.net/projects/mingw-w64/
* Change the architecture to `x86_64` if on a 64-bit system and keep everything else.
* After installation, add the `bin` directory to `PATH`.
    * E.g. `C:\Program Files\mingw-w64\x86_64-8.1.0-posix-seh-rt_v6-rev0\mingw64\bin`

## Lessons Learned

### jmoiron/sqlx

Troubleshooting:

* Problem: `panic: sql: unknown driver "sqlite3" (forgotten import?)`
* Solution: `import _ "github.com/mattn/go-sqlite3"`

* Problem:
  ```
  # github.com/mattn/go-sqlite3
  exec: "gcc": executable file not found in %PATH%
  ```
* Solution: Install https://sourceforge.net/projects/mingw-w64/ (see above).

Good examples:

* https://jmoiron.github.io/sqlx/
* https://github.com/joncrlsn/go-examples/blob/master/sqlx-sqlite.go

* Problem: "missing destination name" error when using `Queryx` and `StructScan`.
* Solutions:
  * Struct fields must be exported.
  * Map the table columns to struct fields with `db:"table-column"`.

## Usage

```
$ go run main.go
Creating phone_numbers.
Adding phone numbers to the table.
Reading from phone_numbers.
Creating unique_numbers.
Adding unique phone numbers to unique_numbers.
Reading unique phone numbers from unique_numbers.
1234567891
1234567892
1234567893
1234567894
1234567890
```
