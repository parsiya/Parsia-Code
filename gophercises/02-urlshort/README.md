# Gophercises - 2 - URL Shortener

## Problem

* https://github.com/gophercises/urlshort
* https://gophercises.com/exercises/urlshort

## Solutions:

* [Normal](normal): Implement the handlers and yaml parser.
* [Bonus](bonus)
    * Add yaml file flag and read data from file if available.
    * Add JSON handler.
    * Skipped: Database.

## Lessons Learned

### http.Handler

* Read this: https://medium.com/@matryer/the-http-handler-wrapper-technique-in-golang-updated-bc7fbcffa702
    * "The idea is that you take in an http.Handler and return a new one that does something else before and/or after calling the ServeHTTP method on the original."
* Then pass the custom handler to `http.ListenAndServe(":8080", customHandler)`