package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"

	"github.com/parsiya/Parsia-Code/gophercises/16-twitter/twit"
)

// Don't panic! These tokens were invalidated after finishing the lesson.
const (
	APIKey    = "SsBJMU0wYP4gMOgFsaGM0iwXO"
	APISecret = "Pw6TmSSMxcSyzkzZoHTPx1IViKBpikxnotHipiZa0piTzuZkCF"
)

var (
	tokenFile       string
	tweetID         string
	numberOfWinners int
)

func init() {
	flag.StringVar(&tokenFile, "tk", "", "Token file with the bearer token")
	flag.StringVar(&tweetID, "id", "", "Tweet ID")
	flag.IntVar(&numberOfWinners, "win", 1, "Number of winners")
	flag.Parse()
}

func main() {

	var cl *twit.TwitterClient
	var err error

	if tweetID == "" {
		log.Printf("Tweet ID is required.")
		return
	}

	if tokenFile != "" {
		log.Printf("Reading token from %s", tokenFile)
		cl, err = twit.NewClientFromFile(tokenFile)
		if err != nil {
			log.Printf("Could not get token from %s: %v", tokenFile, err)
			return
		}
		log.Println("Token read from file")
	} else {
		log.Printf("No token file provided, getting a new bearer token")
		cl = twit.NewClient(APIKey, APISecret)
		if err := cl.GetBearerToken(); err != nil {
			log.Printf("Could not get bearer token: %v", err)
			return
		}
		log.Println("New bearer token acquired")
		log.Println("Saving bearer token to tk.json")
		// Save the token to file.
		if err = cl.SaveToFile("tk.json"); err != nil {
			log.Printf("Could not save token to file: %v", err)
			return
		}
		log.Println("Token saved to tk.json")
	}

	log.Printf("Getting retweeters for tweet ID %s", tweetID)
	// Get retweeters.
	retweeters, err := cl.GetRetweets(tweetID)
	if err != nil {
		log.Printf("Could not get retweeters: %v", err)
		return
	}
	log.Printf("Got %d retweets", len(retweeters))

	// Saving retweeters to file.
	retFile := fmt.Sprintf("retweeters-%s.json", tweetID)
	log.Println("Saving retweeters to", retFile)
	f, err := os.Create(retFile)
	if err != nil {
		log.Printf("Could not create retweeters file: %v", err)
		return
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	if err = enc.Encode(retweeters); err != nil {
		fmt.Printf("Could not save retweeters to file: %v", err)
		return
	}
	log.Println("Saved retweeters to", retFile)

	// Time to shuffle and pick the winners.
	// If number of winners <1, use 1.
	if numberOfWinners < 1 {
		numberOfWinners = 1
	}

	// Using craptographically secure math/rand so our contest is rigged.
	rnd := rand.New(rand.NewSource(time.Now().Unix()))
	rnd.Shuffle(len(retweeters), func(i, j int) {
		retweeters[i], retweeters[j] = retweeters[j], retweeters[i]
	})

	log.Println("Winners:")
	for i := 0; i < numberOfWinners; i++ {
		log.Println(retweeters[i])
	}
}