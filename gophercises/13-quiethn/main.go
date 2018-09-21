package main

// Quiet HackerNews with concurrency and caching.
// For caching we create a map and store the stories, if the id is already in the
// map we do not run getOneStory on it.

import (
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/parsiya/Parsia-Code/gophercises/13-quiethn/hn"
)

var cache = make(map[int]item)
var goroutine int

func main() {
	// parse flags
	var port, numStories int
	flag.IntVar(&port, "port", 3000, "the port to start the web server on")
	flag.IntVar(&numStories, "num_stories", 30, "the number of top stories to display")
	flag.Parse()

	goroutine = 0

	tpl := template.Must(template.ParseFiles("./index.gohtml"))

	http.HandleFunc("/", handler(numStories, tpl))

	// Start the server
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}

func handler(numStories int, tpl *template.Template) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		stories, err := getStories(numStories)
		if err != nil {

			http.Error(w, fmt.Sprintf("Failed to load top stories : %v", err),
				http.StatusInternalServerError)
			return
		}

		data := templateData{
			Stories: stories,
			Time:    time.Now().Sub(start),
		}
		err = tpl.Execute(w, data)
		if err != nil {
			http.Error(w, "Failed to process the template", http.StatusInternalServerError)
			return
		}
	})
}

func isStoryLink(item item) bool {
	return item.Type == "story" && item.URL != ""
}

func parseHNItem(hnItem hn.Item) item {
	ret := item{Item: hnItem}
	url, err := url.Parse(ret.URL)
	if err == nil {
		ret.Host = strings.TrimPrefix(url.Hostname(), "www.")
	}
	return ret
}

// item is the same as the hn.Item, but adds the Host field
type item struct {
	hn.Item
	Host string
}

type templateData struct {
	Stories []item
	Time    time.Duration
}

// getStories returns the top n stories of HN.
// Supposed to increase performance.
func getStories(numStories int) ([]item, error) {

	var stories []item
	// We are not touching this part.
	var client hn.Client
	ids, err := client.TopItems()
	if err != nil {
		return stories, err
	}

	// Concurrency happens here.
	storyChannel := make(chan item, numStories)

Mainloop:
	for _, id := range ids {
		if st, exists := cache[id]; exists {
			// fmt.Printf("story id %d exists, reading from cache.\n", id)
			storyChannel <- st
			continue
		}
		select {
		case story := <-storyChannel:
			// fmt.Printf("adding story id %d to cache.\n", story.ID)
			cache[story.ID] = story
			stories = append(stories, story)
			if len(stories) == numStories {
				break Mainloop
			}
		default:
			if goroutine == numStories {
				// fmt.Println("goroutine == numStories\n", goroutine)
				continue
			}
			go getOneStory(id, client, storyChannel, goroutine)
			goroutine++
		}
	}
	// fmt.Println("returning len(stories)", len(stories))
	return stories, nil
}

// getOneStory downloads one story and returns the content.
func getOneStory(id int, c hn.Client, channel chan item, counter int) {
	// defer wg.Done()
	var i item
	// fmt.Printf("getting item %d inside getOneStory number %d\n", id, counter)
	hnItem, err := c.GetItem(id)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("parsing item %d\n", id)
	i = parseHNItem(hnItem)
	if !isStoryLink(i) {
		goroutine--
		// fmt.Printf("returning because item %d is not a story.\n", id)
		return
	}
	// fmt.Printf("Adding item %d to channel.\n", id)
	channel <- i
}
