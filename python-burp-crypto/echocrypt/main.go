package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"
)

func main() {
	// Ideally check key and iv for length before passing them to functions.
	key := []byte("0123456789012345")
	iv := []byte("9876543210987654")
	msg := []byte("Hello AES, my old friend")

	// Create proxy URL. Assume Burp's default listener.
	proxyURL, err := url.Parse("http://localhost:8080")
	if err != nil {
		panic(err)
	}

	// Server endpoint.
	serverPort := "9090"
	serverAddr := "http://127.0.0.1:" + serverPort

	go Client(msg, key, iv, proxyURL, serverAddr)
	go Server(key, iv, serverPort)

	for {
	}
}

// client.go
// Client encrypts msg with AES-CFB algorithm using key and iv.
// Encrypted message is repeatedly sent in a POST reqiest to endpoint via proxy.
func Client(msg, key, iv []byte, proxy *url.URL, serverAddr string) error {
	// Encrypt the msg.
	ciphertext, err := Encrypt(msg, key, iv)
	if err != nil {
		return err
	}

	for {
		// Sleep for 5 seconds.
		time.Sleep(5 * time.Second)
		// Create an io.Reader from ciphertext.
		cipherReader := bytes.NewReader(ciphertext)
		// Now we need to send it out.
		// Create a transport that uses the proxy.
		transport := &http.Transport{
			Proxy: http.ProxyURL(proxy),
		}
		// Create an http client that uses the transport.
		client := &http.Client{
			Transport: transport,
			Timeout:   0, // 0: No timeout.
		}
		log.Printf("Client: Sending to server: %s\n", string(msg))
		// Create a new POST request.
		resp, err := client.Post(serverAddr, "application/octet-stream", cipherReader)
		if err != nil {
			log.Printf("Client: POST error - %s\n", err.Error())
			continue
		}
		// Read the response.
		defer resp.Body.Close()
		responseBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("Client: Read response error - %s\n", err.Error())
			continue
		}
		defer resp.Body.Close()
		// Decrypt and print it.
		plaintext, err := Decrypt(responseBody, key, iv)
		if err != nil {
			log.Printf("Client: Decryption error - %s\n", err.Error())
			continue
		}
		log.Printf("Client: Received from server: %s\n", string(plaintext))
	}
	return nil
}

// server.go
// Server listens on 127.0.0.1:port, attempts to decrypt any message received with
// key and iv using AES-CFB. Echoes messages back to client as-is.
func Server(key, iv []byte, port string) {
	log.Printf("Server: Starting local server on port %s\n", port)
	// Using an inline handler to use key and iv.
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		// Read requests' body.
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			w.Write([]byte(fmt.Sprintf("Server: Error - %s\n", err.Error())))
			return
		}
		defer req.Body.Close()
		// Attempt to decrypt body.
		plaintext, err := Decrypt(body, key, iv)
		if err != nil {
			w.Write([]byte(fmt.Sprintf("Server: Decryption error - %s\n", err.Error())))
			return
		}
		log.Printf("Server: Received and decrypted %s\n", string(plaintext))
		// Send the body back.
		w.Write(body)
	})
	http.ListenAndServe(":"+port, nil)
}

// crypto.go
// Encrypt encrypts the plaintext with key and iv using AES-CFB and returns it in base64.
func Encrypt(plaintext, key, iv []byte) ([]byte, error) {
	// Create ciphertext.
	ciphertext := make([]byte, len(plaintext))
	// Create AES cipher.
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// Get AES-CFB stream encrypted.
	stream := cipher.NewCFBEncrypter(aesBlock, iv)
	// Encrypt the msg and store the results in ciphertext.
	stream.XORKeyStream(ciphertext, plaintext)
	// Base64 encode it.
	encodedCiphertext := make([]byte, base64.StdEncoding.EncodedLen(len(ciphertext)))
	base64.StdEncoding.Encode(encodedCiphertext, ciphertext)
	return encodedCiphertext, nil
}

// Decrypt decodes the ciphertext from base64 then decrypts it key and iv using AES-CFB.
func Decrypt(ciphertext, key, iv []byte) ([]byte, error) {
	// Decode ciphertext from base64.
	decodedCiphertext := make([]byte, base64.StdEncoding.DecodedLen(len(ciphertext)))
	base64.StdEncoding.Decode(decodedCiphertext, ciphertext)
	plaintext := make([]byte, len(ciphertext))
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCFBDecrypter(aesBlock, iv)
	stream.XORKeyStream(plaintext, decodedCiphertext)
	return plaintext, nil
}
