# Gophercises - 17 - Secrets API and CLI

## Problem

* https://github.com/gophercises/secret
* https://gophercises.com/exercises/secret


## Solution

* [main.go](main.go): Main functionality. Create keystore, add/update/list/delete keys.
* [keystore/keystore.go](keystore/keystore.go): Keystore package.

## Lessons Learned

### Chaining Reader and Writer Interfaces
This is pretty cool. You can see it inside `Encrypter` and `Decrypter`.

In short, you pass an `io.Reader` or `io.Writer` to another and chain them. Then you write to one (or read from one) and encryption/decryption works. We have already seen this in a previous lesson where we used `json.NewDecoder/NewEncoder` on files or buffers.

### io.TeeReader(r io.Reader, w io.Writer) io.Reader
"TeeReader returns a Reader that writes to w what it reads from r. All reads from r performed through it are matched with corresponding writes to w. There is no internal buffering ..."

* https://golang.org/pkg/io/#TeeReader

I did not use it in this lesson, but seems like a useful thing.

### Pass Arguments to Delve Debugger in VS Code
Pass the arguments inside `launch.json` like this.

``` json
"args": [
    "get",
    "test",
    "yolo",
    "key3",
],
```

### Encrypter and Decrypter
I wasted a lot of time (a Sunday) debugging the code because my decrypted values where only correct for the first block. Finally, I saw I am encrypting again inside `Decrypter`. On a positive note, I learned how to use Delve debugger and looked at the internals of json encoder/decoder.

## Usage

```
$ go run main.go
NAME:
   secret - secret is simple encrypted keystore.

USAGE:
   main.exe [global options] command [command options] [arguments...]

COMMANDS:
     create, c         Create a new keystore.
                       secret create [filename] [encryptionKey]
     set, s, add       Set a key/value pair in the keystore.
                       secret set [filename] [encryptionKey] [key] [value]
     get, g, retrieve  Get the value of a key from the keystore.
                       secret get [filename] [encryptionKey] [key]
     del, d, delete    Delete a key from the keystore.
                       secret del [filename] [encryptionKey] [key]
     list, l           List all keys in the keystore.
                       secret list [filename] [encryptionKey]
     help, h           Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h  show help
No commands provided.
exit status 2

$go run main.go create test.enc pass
Keystore created at test.enc.

$ go run main.go add test.enc pass key1 val1
Added key1 to keystore.
KeyStore:
Path: test.enc
Number of keys:1

$ go run main.go add test.enc pass key2 val2
Added key2 to keystore.
KeyStore:
Path: test.enc
Number of keys:2

$ go run main.go list test.enc pass
Keys in the keystore
key1
key2

$ go run main.go del test.enc pass key2
Key key2 (if exists) deleted from the keystore.
KeyStore:
Path: test.enc
Number of keys:1

$ go run main.go list test.enc pass
Keys in the keystore
key1

$ go run main.go get test.enc pass key2
keystore.Get: key2 key does not exist
exit status 3

$ go run main.go get test.enc pass key1
Value of key1 key is: val1.
KeyStore:
Path: test.enc
Number of keys:1
```