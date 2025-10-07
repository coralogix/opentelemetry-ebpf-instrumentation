package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

func main() {
	for {
		resp, err := http.Get("http://localhost:8080")
		if err != nil {
			log.Printf("Error making request: %v\n", err)
		} else {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Printf("Error reading response body: %v\n", err)
			} else {
				fmt.Printf("Received from server: %s\n", string(body))
			}
			resp.Body.Close()
		}
		time.Sleep(time.Second)
	}
}
