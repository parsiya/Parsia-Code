# Gophercises - 16 - Twitter Contest CLI

## Problem

* https://github.com/gophercises/twitter
* https://gophercises.com/exercises/twitter


## Solution

* [main.go](main.go): Main functionality. Submit an ID, get the retweets, and print n winners.
    * Supports using tokens stored in file instead of getting them every time.
* [twit/twitter.go](twit/twitter.go): Twit package.

## Lessons Learned

### json.NewDecoder json.NewEncoder
When decoding from or encoding to an `io.Reader/Writer` (e.g. file, HTTP response), we can do this:

``` go
var []obj MyStruct
// fill in []obj

// File to encode stuff to.
f, _ := os.Create("whatever.txt")
enc := json.NewEncoder(f)
if err := enc.Encode(obj); err != nil {
    // Handle error
}

// Now json is saved to file.
```

To decode, we can do something similar with an `io.Reader` (e.g. file).

``` go
var []obj2 MyStruct

f, _ := os.Open("whatever.txt")
dec := json.NewDecoder(f)
if err := enc.Decode(&obj2); err != nil {
    // Handle error
}

// Now json is populated from file.
```

### Twitter Application-Only Auth-Flow
Docs: https://developer.twitter.com/en/docs/basics/authentication/overview/application-only

1. Create an application and a set of read-only consumer API keys. Twitter will ask you to write 300 words about your application and other crap.
2. Create the authorization token by combining the key and secret and then base64 encoding them. `base64(Key:Secret)`.
    * Use [request.SetBasicAuth(Key,Secret)](https://golang.org/pkg/net/http/?#Request.SetBasicAuth) in the `http` package.
3. Send the following POST request to https://api.twitter.com/oauth2/token to get the bearer token.
    ```
    POST /oauth2/token HTTP/1.1
    Host: api.twitter.com
    User-Agent: Whatever
    Authorization: Basic [token from step 2]
    Content-Type: application/x-www-form-urlencoded;charset=UTF-8
    Accept-Encoding: gzip

    grant_type=client_credentials
    ```
4. Response will have the bearer token if successful (and a 200 OK status)
   ``` json
   {"token_type":"bearer","access_token":"AAAAAAAAAAAAAAAAAAAAAAAAAA"}
   ```
5. Use the token in the header of every request `Authorization: Bearer AAAAAAAAAAAAAAAAAAAAAAAAAA`
6. ???
7. Profit

### Get Retweeters
GET request to https://api.twitter.com/1.1/statuses/retweets/tweetID.json?count=100.

* https://developer.twitter.com/en/docs/tweets/post-and-engage/api-reference/get-statuses-retweets-id

Results has these fields.

``` json
[
  {
    // ...
    "user": {
      // ...
      "id": 281679947,
      "id_str": "281679947",
      "is_translation_enabled": false,
      "is_translator": false,
      "lang": "en",
      "listed_count": 43,
      "location": "NYC",
      "name": "Christine Romo",
      // ...
      "screen_name": "romoabcnews",
    }
  }
]
```

We want to read `id_str` and `screen_name` so we unmarshal the JSON to `[]Retweeter` where:

``` go
// User represents a user.
type User struct {
	Id   string `json:"id_str"`
	Name string `json:"screen_name"`
}

// Retweeter represents a user who has retweeted the content.
type Retweeter struct {
	TwitterUser User `json:"user"`
}
```
## Usage

```
$ go run main.go --help
Usage of main.exe:
  -id string
        Tweet ID
  -tk string
        Token file with the bearer token
  -win int
        Number of winners (default 1)
exit status 2

$ go run main.go -id 1019637438115770368 -tk tk.json -win 3
2018/09/26 00:28:53 Reading token from tk.json
2018/09/26 00:28:53 Token read from file
2018/09/26 00:28:53 Getting retweeters for tweet ID 1019637438115770368
2018/09/26 00:28:53 Got 85 retweets
2018/09/26 00:28:53 Saving retweeters to retweeters-1019637438115770368.json
2018/09/26 00:28:53 Saved retweeters to retweeters-1019637438115770368.json
2018/09/26 00:28:53 Winners:
2018/09/26 00:28:53 {{2120351 Barlow}}
2018/09/26 00:28:53 {{967754071066271751 dj_mikeyrowley}}
2018/09/26 00:28:53 {{845067737428869121 d3f3__}}
```