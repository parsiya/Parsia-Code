# Gophercises - 19 - Building Images

## Problem

* https://github.com/gophercises/image
* https://gophercises.com/exercises/image


## Solution

* [basic/main.go](basic/main.go): Pixel by pixel manipulation to make bars.\
    * Nothing groundbreaking here, just nested `for`s.
* [draw/main.go](main.go): Using the [draw](https://golang.org/pkg/image/draw/) package.
* [main.go](main.go): Using the [svgo](https://github.com/ajstarks/svgo) package.
    * [svg.go](svg.go): Contains `drawSVG` which creates the same ole' bar chart and `usageSVG` which creates the usage chart.

## Lessons Learned
Not much, learned how to use the packages which was neat.