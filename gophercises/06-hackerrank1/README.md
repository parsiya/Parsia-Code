# Gophercises - 6 - Hacker Rank 1 - strings and bytes

## Problem

* https://github.com/gophercises/hr1
* https://gophercises.com/exercises/hr1
    * https://www.hackerrank.com/challenges/camelcase/problem
    * https://www.hackerrank.com/challenges/caesar-cipher-1/problem

## Solutions

* [Camel Case](camelcase/main.go): Calculate the number of capital words and return + 1. The problem doesn't seem to care about acronyms being uppercase. Only the first letter is, regardless of word type. "For each of the subsequent words, the first letter is uppercase and rest of the letters are lowercase."
  ``` go
  $ go run main.go --help
  -i string
        camelCase string (default "saveChangesInTheEditor")

  $ go run main.go --i oneTwoThree
  Number of words in oneTwoThree: 3
  ```

* [Caesar Cipher](caesarcipher/main.go): Implement Caesar cipher. Only encrypt letters. Input has dashes instead of space that should not be encrypted.
  ``` go
  $ go run main.go --help
  -key int
        key - a.k.a. how many positions to shift
  -len int
        length of plaintext
  -plaintext string
        plaintext

  $ go run main.go --plaintext middle-Outz --len 11 --key 2
    okffng-Qwvz
  ```

## Lessons Learned

### Range on string returns Runes

* These runes must be converted to string before usage with `string(ch)`

### String vs. Rune

* `"a"` is a string, `'a'` is a rune.
* rune to string with `string('a')`.
* string to rune with `rune("a")`.
* string to int with `int("a")`.
