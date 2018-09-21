package hn

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setup() (string, func()) {
	mux := http.NewServeMux()
	mux.HandleFunc("/topstories.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "[0,1,2,3,4]")
	})
	mux.HandleFunc("/item/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "{\"by\":\"test_user\",\"descendants\":10,\"id\":1,\"kids\":[16732999,16729637,16729517,16729595],\"score\":34,\"time\":1522599083,\"title\":\"Test Story Title\",\"type\":\"story\",\"url\":\"https://www.test-story.com\"}")
	})
	server := httptest.NewServer(mux)
	return server.URL, func() {
		server.Close()
	}
}

func TestClient_TopItems(t *testing.T) {
	baseURL, teardown := setup()
	defer teardown()

	c := Client{
		apiBase: baseURL,
	}
	ids, err := c.TopItems()
	if err != nil {
		t.Errorf("client.TopItems() received an error: %s", err.Error())
	}
	if len(ids) != 5 {
		t.Errorf("len(ids): want %d, got %d", 5, len(ids))
	}
}

func TestClient_defaultify(t *testing.T) {
	var c Client
	c.defaultify()
	if c.apiBase != apiBase {
		t.Errorf("c.apiBase: want %s, got %s", apiBase, c.apiBase)
	}
}

func TestClient_GetItem(t *testing.T) {
	baseURL, teardown := setup()
	defer teardown()

	c := Client{
		apiBase: baseURL,
	}
	item, err := c.GetItem(1)
	if err != nil {
		t.Errorf("client.GetItem() received an error: %s", err.Error())
	}
	// If this stuff errors it means our JSON is incorrect, which is unlikely, so
	// we can just check one field and consider that enough
	if item.By != "test_user" {
		t.Errorf("item.By: want %s, got %s", "test_user", item.By)
	}
}
