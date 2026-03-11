package gate

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoadStarterCatalog(t *testing.T) {
	cat, err := LoadStarterCatalog()
	if err != nil {
		t.Fatal(err)
	}

	// Check profiles exist
	expectedProfiles := []string{"fun", "hackernews", "httpbin", "dadjokes", "trivia", "dogs"}
	for _, name := range expectedProfiles {
		if _, ok := cat.Profiles[name]; !ok {
			t.Errorf("missing profile %q", name)
		}
	}

	// Check recipes exist
	expectedRecipes := []string{
		"leet.translate", "ascii.artify",
		"hn.top-stories", "hn.get-item",
		"httpbin.echo", "httpbin.headers",
		"jokes.dad", "trivia.random",
		"dogs.random", "dogs.breed",
	}
	for _, name := range expectedRecipes {
		if _, ok := cat.Recipes[name]; !ok {
			t.Errorf("missing recipe %q", name)
		}
	}

	// Validate all recipes against their profiles
	for _, name := range cat.ListRecipes() {
		if err := cat.ValidateRecipe(name); err != nil {
			t.Errorf("recipe validation failed: %v", err)
		}
	}
}

func TestRecipeCatalog_GetRecipe(t *testing.T) {
	cat, _ := LoadStarterCatalog()

	r, err := cat.GetRecipe("jokes.dad")
	if err != nil {
		t.Fatal(err)
	}
	if r.Service != "dadjokes" {
		t.Fatalf("expected service dadjokes, got %s", r.Service)
	}
	if r.Threshold != 1 {
		t.Fatalf("expected threshold 1, got %d", r.Threshold)
	}

	_, err = cat.GetRecipe("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent recipe")
	}
}

func TestRecipeCatalog_ValidateRecipe_BadService(t *testing.T) {
	cat := NewRecipeCatalog()
	cat.AddRecipe(&Recipe{Name: "bad", Service: "missing", Verb: "GET", Endpoint: "/foo"})

	err := cat.ValidateRecipe("bad")
	if err == nil || !strings.Contains(err.Error(), "unknown service") {
		t.Fatalf("expected unknown service error, got %v", err)
	}
}

func TestRecipeCatalog_ValidateRecipe_BadEndpoint(t *testing.T) {
	cat := NewRecipeCatalog()
	cat.AddProfile(&Profile{
		Service: "test",
		Endpoints: []EndpointSpec{
			{Path: "/real", Verb: "GET"},
		},
	})
	cat.AddRecipe(&Recipe{Name: "bad", Service: "test", Verb: "GET", Endpoint: "/fake"})

	err := cat.ValidateRecipe("bad")
	if err == nil || !strings.Contains(err.Error(), "not in profile") {
		t.Fatalf("expected not-in-profile error, got %v", err)
	}
}

func TestFunServer_Leet(t *testing.T) {
	srv := httptest.NewServer(NewFunServer())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/leet", "application/json",
		strings.NewReader(`{"text":"Hello World"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)

	if result["output"] != "H3110 W0r1d" {
		t.Fatalf("leet output = %q, want H3110 W0r1d", result["output"])
	}
}

func TestFunServer_ASCII(t *testing.T) {
	srv := httptest.NewServer(NewFunServer())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/ascii", "application/json",
		strings.NewReader(`{"text":"HI"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result map[string]string
	json.Unmarshal(body, &result)

	art := result["art"]
	if !strings.Contains(art, "█") {
		t.Fatalf("ASCII art should contain block chars, got: %s", art)
	}
	if result["input"] != "HI" {
		t.Fatalf("input should be HI, got %s", result["input"])
	}
}

func TestFunServer_ASCII_GET(t *testing.T) {
	srv := httptest.NewServer(NewFunServer())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/ascii?text=OK")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)

	if result["input"] != "OK" {
		t.Fatalf("input should be OK, got %s", result["input"])
	}
}

func TestFunServer_Health(t *testing.T) {
	srv := httptest.NewServer(NewFunServer())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)

	if result["status"] != "ok" {
		t.Fatalf("health status = %q", result["status"])
	}
}
