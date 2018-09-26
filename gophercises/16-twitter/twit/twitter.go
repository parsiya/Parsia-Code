package twit

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"golang.org/x/oauth2"
)

type TwitterClient struct {
	*http.Client
	key    string
	secret string
	Token  oauth2.Token
}

// NewClient creates a new twitter client but does not get a token.
func NewClient(key, secret string) *TwitterClient {
	var t TwitterClient
	t.Client = &http.Client{}
	t.key = key
	t.secret = secret
	return &t
}

// GetBearerToken authenticates to the Twitter API and obtains a bearer token.
func (t *TwitterClient) GetBearerToken() error {

	if t.key == "" || t.secret == "" {
		return fmt.Errorf("Key and Secret are not set.")
	}

	// Last param is an io.Reader. Make an io.Reader from the parameters.
	getToken, err := http.NewRequest("POST", "https://api.twitter.com/oauth2/token",
		strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		return err
	}

	// Don't need to do the basic auth ourselves.
	getToken.SetBasicAuth(t.key, t.secret)

	// Set the required header.
	getToken.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")

	// Set User-Agent.
	getToken.Header.Set("User-Agent", "Gophercises-1")

	var client http.Client

	resp, err := client.Do(getToken)
	if err != nil {
		return err
	}

	b, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return err
	}

	if err := json.Unmarshal(b, &t.Token); err != nil {
		return err
	}
	return nil
}

// SaveToFile marshals token and writes it to a file.
func (t *TwitterClient) SaveToFile(fi string) error {
	f, err := os.Create(fi)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	if err := enc.Encode(t.Token); err != nil {
		return err
	}
	return nil

}

// NewClientFromFile reads a json file and creates a new Twitter client.
func NewClientFromFile(fi string) (*TwitterClient, error) {
	f, err := os.Open(fi)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var tw TwitterClient
	tw.Client = &http.Client{}
	dec := json.NewDecoder(f)
	if err := dec.Decode(&tw.Token); err != nil {
		return nil, err
	}
	return &tw, nil
}

// User represents a user.
type User struct {
	Id   string `json:"id_str"`
	Name string `json:"screen_name"`
}

// Retweeter represents a user who has retweeted the content.
type Retweeter struct {
	TwitterUser User `json:"user"`
}

// https://api.twitter.com/1.1/statuses/retweets/:id.json

// GetRetweets returns a list of screen_name and ids of people who have
// retweeted a specific tweet.
func (t *TwitterClient) GetRetweets(id string) ([]Retweeter, error) {

	var re []Retweeter
	u := fmt.Sprintf("https://api.twitter.com/1.1/statuses/retweets/%s.json?count=100", id)
	getRetweets, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}

	// Set the bearer token.
	t.Token.SetAuthHeader(getRetweets)

	resp, err := t.Do(getRetweets)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Decode the response using a json decoder this time.
	// Alternatively, we could read all and json.Unmarshal.
	jsDecoder := json.NewDecoder(resp.Body)
	if err := jsDecoder.Decode(&re); err != nil {
		return nil, err
	}

	// b, err := ioutil.ReadAll(resp.Body)
	// if err != nil {
	// 	return nil, err
	// }
	// fmt.Println(string(b))

	return re, nil
}
