# Gophercises - 1 - Quiz

## Problem:

* https://github.com/gophercises/quiz
* https://gophercises.com/exercises/quiz

## Solutions:

* [Part 1](part1): Read problems from csv and do the quiz.
* [Part 2](part2): Stop the quiz after a specific time using timers.
* [Bonus and Cleanup](bonus-cleanup): Implement bonus features. Lowercase, trim, and shuffle.

## Lessons Learned:

### Timers

* Read this: https://gobyexample.com/timers
* Block with `<-timerVar.C`
* Stop the timer with `stop := timerVar.Stop()`
    * If timer is stopped, `stop` will be `true`.
* **Stop doesn't unblock the channel.** If you stop the timer, the channel will remain blocked.
    * Here's code based on gobyexample that will dead-lock if executed.
    ``` go
    package main

    import "time"
    import "fmt"

    func main() {

        timer2 := time.NewTimer(10 * time.Second)
        stop2 := timer2.Stop()
        if stop2 {
            fmt.Println("Timer 2 stopped")
        }
        <-timer2.C
    }
    ```
    * Instead, use `timerVar.Reset(0)`. This will stop the timer and unblock the channel.

### rand.Shuffle

* https://golang.org/pkg/math/rand/#Shuffle
* Remember to seed a rand object.
    * `rnd := rand.New(rand.NewSource(time.Now().Unix()))`
* Needs a swap function of this type `func(i, j int)`.
    * Inside the swap function (does not need to be named `swap`), do the swaps.

``` go
func (e *Exam) Shuffle() {
	rnd := rand.New(rand.NewSource(time.Now().Unix()))
	rnd.Shuffle(len(e.problems), func(i, j int) {
		e.problems[i], e.problems[j] = e.problems[j], e.problems[i]
	})
}
```


