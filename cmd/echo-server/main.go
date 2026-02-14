// Echo server for qntm-gate integration testing.
// Echoes back HTTP method, path, headers, auth, and body as JSON.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
)

func main() {
	port := flag.Int("port", 9090, "echo server port")
	flag.Parse()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("ECHO: %s %s", r.Method, r.URL.Path)
		body, _ := io.ReadAll(r.Body)
		defer r.Body.Close()

		headers := make(map[string]string)
		for k, v := range r.Header {
			if len(v) > 0 {
				headers[k] = v[0]
			}
		}

		auth := r.Header.Get("Authorization")
		resp := map[string]interface{}{
			"method":      r.Method,
			"path":        r.URL.Path,
			"had_auth":    auth != "",
			"auth_header": auth,
			"headers":     headers,
		}
		if len(body) > 0 {
			if json.Valid(body) {
				resp["body"] = json.RawMessage(body)
			} else {
				resp["body"] = string(body)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("qntm echo server on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
