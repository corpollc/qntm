package gate

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// NewFunServer creates an HTTP server with leet speak and ASCII art endpoints.
// Used as a self-contained test target for gate recipes.
func NewFunServer() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/leet", handleLeet)
	mux.HandleFunc("/ascii", handleASCII)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "service": "fun"})
	})

	return mux
}

var leetMap = map[rune]string{
	'a': "4", 'A': "4",
	'b': "8", 'B': "8",
	'e': "3", 'E': "3",
	'g': "6", 'G': "6",
	'i': "1", 'I': "1",
	'l': "1", 'L': "1",
	'o': "0", 'O': "0",
	's': "5", 'S': "5",
	't': "7", 'T': "7",
	'z': "2", 'Z': "2",
}

func toLeet(s string) string {
	var b strings.Builder
	for _, c := range s {
		if rep, ok := leetMap[c]; ok {
			b.WriteString(rep)
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func handleLeet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}

	var req struct {
		Text string `json:"text"`
	}
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil || req.Text == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "JSON body with 'text' field required"})
		return
	}

	result := toLeet(req.Text)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"input":  req.Text,
		"output": result,
	})
}

// Simple block-letter ASCII art font (5 lines tall)
var asciiFont = map[rune][5]string{
	'A': {"  █  ", " █ █ ", "█████", "█   █", "█   █"},
	'B': {"████ ", "█   █", "████ ", "█   █", "████ "},
	'C': {" ████", "█    ", "█    ", "█    ", " ████"},
	'D': {"████ ", "█   █", "█   █", "█   █", "████ "},
	'E': {"█████", "█    ", "████ ", "█    ", "█████"},
	'F': {"█████", "█    ", "████ ", "█    ", "█    "},
	'G': {" ████", "█    ", "█  ██", "█   █", " ████"},
	'H': {"█   █", "█   █", "█████", "█   █", "█   █"},
	'I': {"█████", "  █  ", "  █  ", "  █  ", "█████"},
	'J': {"█████", "    █", "    █", "█   █", " ███ "},
	'K': {"█   █", "█  █ ", "███  ", "█  █ ", "█   █"},
	'L': {"█    ", "█    ", "█    ", "█    ", "█████"},
	'M': {"█   █", "██ ██", "█ █ █", "█   █", "█   █"},
	'N': {"█   █", "██  █", "█ █ █", "█  ██", "█   █"},
	'O': {" ███ ", "█   █", "█   █", "█   █", " ███ "},
	'P': {"████ ", "█   █", "████ ", "█    ", "█    "},
	'Q': {" ███ ", "█   █", "█ █ █", "█  █ ", " ██ █"},
	'R': {"████ ", "█   █", "████ ", "█  █ ", "█   █"},
	'S': {" ████", "█    ", " ███ ", "    █", "████ "},
	'T': {"█████", "  █  ", "  █  ", "  █  ", "  █  "},
	'U': {"█   █", "█   █", "█   █", "█   █", " ███ "},
	'V': {"█   █", "█   █", "█   █", " █ █ ", "  █  "},
	'W': {"█   █", "█   █", "█ █ █", "██ ██", "█   █"},
	'X': {"█   █", " █ █ ", "  █  ", " █ █ ", "█   █"},
	'Y': {"█   █", " █ █ ", "  █  ", "  █  ", "  █  "},
	'Z': {"█████", "   █ ", "  █  ", " █   ", "█████"},
	' ': {"     ", "     ", "     ", "     ", "     "},
	'!': {"  █  ", "  █  ", "  █  ", "     ", "  █  "},
	'?': {" ███ ", "█   █", "  █  ", "     ", "  █  "},
	'.': {"     ", "     ", "     ", "     ", "  █  "},
	'0': {" ███ ", "█  ██", "█ █ █", "██  █", " ███ "},
	'1': {"  █  ", " ██  ", "  █  ", "  █  ", "█████"},
	'2': {" ███ ", "█   █", "  █  ", " █   ", "█████"},
	'3': {" ███ ", "█   █", "  ██ ", "█   █", " ███ "},
	'4': {"█   █", "█   █", "█████", "    █", "    █"},
	'5': {"█████", "█    ", "████ ", "    █", "████ "},
	'6': {" ███ ", "█    ", "████ ", "█   █", " ███ "},
	'7': {"█████", "    █", "   █ ", "  █  ", "  █  "},
	'8': {" ███ ", "█   █", " ███ ", "█   █", " ███ "},
	'9': {" ███ ", "█   █", " ████", "    █", " ███ "},
}

func toASCIIArt(text string) string {
	text = strings.ToUpper(text)
	lines := [5]strings.Builder{}

	for _, ch := range text {
		glyph, ok := asciiFont[ch]
		if !ok {
			glyph = asciiFont['?']
		}
		for i := 0; i < 5; i++ {
			lines[i].WriteString(glyph[i])
			lines[i].WriteString(" ")
		}
	}

	var result strings.Builder
	for i := 0; i < 5; i++ {
		result.WriteString(lines[i].String())
		if i < 4 {
			result.WriteString("\n")
		}
	}
	return result.String()
}

func handleASCII(w http.ResponseWriter, r *http.Request) {
	// Support both GET ?text=... and POST {"text": "..."}
	var text string

	if r.Method == http.MethodGet {
		text = r.URL.Query().Get("text")
	} else if r.Method == http.MethodPost {
		var req struct {
			Text string `json:"text"`
		}
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &req)
		text = req.Text
	} else {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET or POST required"})
		return
	}

	if text == "" {
		text = "HELLO"
	}
	if len(text) > 40 {
		text = text[:40]
	}

	art := toASCIIArt(text)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"input": text,
		"art":   fmt.Sprintf("\n%s", art),
	})
}
