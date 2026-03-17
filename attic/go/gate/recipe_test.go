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

func TestResolveRecipe_PathParamSubstitution(t *testing.T) {
	recipe := &Recipe{
		Name:     "test.path",
		Verb:     "GET",
		Endpoint: "/item/{id}.json",
		TargetURL: "https://example.com/v0/item/{id}.json",
		PathParams: []RecipeParam{
			{Name: "id", Description: "Item ID", Required: true, Type: "string"},
		},
	}

	ep, url, body, err := ResolveRecipe(recipe, map[string]string{"id": "12345"})
	if err != nil {
		t.Fatal(err)
	}
	if ep != "/item/12345.json" {
		t.Fatalf("endpoint = %q, want /item/12345.json", ep)
	}
	if url != "https://example.com/v0/item/12345.json" {
		t.Fatalf("targetURL = %q, want https://example.com/v0/item/12345.json", url)
	}
	if body != nil {
		t.Fatalf("expected nil body for GET, got %s", body)
	}
}

func TestResolveRecipe_MissingRequiredPathParam(t *testing.T) {
	recipe := &Recipe{
		Name:     "test.path",
		Verb:     "GET",
		Endpoint: "/item/{id}.json",
		TargetURL: "https://example.com/v0/item/{id}.json",
		PathParams: []RecipeParam{
			{Name: "id", Description: "Item ID", Required: true, Type: "string"},
		},
	}

	_, _, _, err := ResolveRecipe(recipe, map[string]string{})
	if err == nil {
		t.Fatal("expected error for missing required path param")
	}
	if !strings.Contains(err.Error(), "missing required path parameter") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveRecipe_DefaultPathParam(t *testing.T) {
	recipe := &Recipe{
		Name:     "test.default",
		Verb:     "GET",
		Endpoint: "/breed/{breed}/images/random",
		TargetURL: "https://example.com/breed/{breed}/images/random",
		PathParams: []RecipeParam{
			{Name: "breed", Description: "Breed", Required: true, Default: "labrador", Type: "string"},
		},
	}

	ep, url, _, err := ResolveRecipe(recipe, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if ep != "/breed/labrador/images/random" {
		t.Fatalf("endpoint = %q, want /breed/labrador/images/random", ep)
	}
	if url != "https://example.com/breed/labrador/images/random" {
		t.Fatalf("targetURL = %q", url)
	}
}

func TestResolveRecipe_BodyBuilding(t *testing.T) {
	recipe := &Recipe{
		Name:     "test.body",
		Verb:     "POST",
		Endpoint: "/leet",
		TargetURL: "http://localhost:9090/leet",
		BodySchema: json.RawMessage(`{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}`),
	}

	ep, url, body, err := ResolveRecipe(recipe, map[string]string{"text": "Hello World"})
	if err != nil {
		t.Fatal(err)
	}
	if ep != "/leet" {
		t.Fatalf("endpoint = %q", ep)
	}
	if url != "http://localhost:9090/leet" {
		t.Fatalf("targetURL = %q", url)
	}

	var bodyMap map[string]interface{}
	if err := json.Unmarshal(body, &bodyMap); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if bodyMap["text"] != "Hello World" {
		t.Fatalf("body text = %q, want Hello World", bodyMap["text"])
	}
}

func TestResolveRecipe_MissingRequiredBodyParam(t *testing.T) {
	recipe := &Recipe{
		Name:     "test.body",
		Verb:     "POST",
		Endpoint: "/leet",
		TargetURL: "http://localhost:9090/leet",
		BodySchema: json.RawMessage(`{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}`),
	}

	_, _, _, err := ResolveRecipe(recipe, map[string]string{})
	if err == nil {
		t.Fatal("expected error for missing required body param")
	}
	if !strings.Contains(err.Error(), "missing required body parameter") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveRecipe_QueryParams(t *testing.T) {
	recipe := &Recipe{
		Name:     "test.query",
		Verb:     "GET",
		Endpoint: "/search",
		TargetURL: "https://example.com/search",
		QueryParams: []RecipeParam{
			{Name: "term", Description: "Search term", Required: true, Type: "string"},
			{Name: "limit", Description: "Result limit", Required: false, Default: "10", Type: "integer"},
		},
	}

	_, url, _, err := ResolveRecipe(recipe, map[string]string{"term": "golang"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(url, "term=golang") {
		t.Fatalf("targetURL missing term param: %q", url)
	}
	if !strings.Contains(url, "limit=10") {
		t.Fatalf("targetURL missing default limit param: %q", url)
	}
}

func TestResolveRecipe_NoParamsGET(t *testing.T) {
	recipe := &Recipe{
		Name:     "test.simple",
		Verb:     "GET",
		Endpoint: "/topstories.json",
		TargetURL: "https://example.com/v0/topstories.json",
	}

	ep, url, body, err := ResolveRecipe(recipe, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ep != "/topstories.json" {
		t.Fatalf("endpoint = %q", ep)
	}
	if url != "https://example.com/v0/topstories.json" {
		t.Fatalf("targetURL = %q", url)
	}
	if body != nil {
		t.Fatalf("expected nil body, got %s", body)
	}
}

func TestResolveRecipe_MultiplePathParams(t *testing.T) {
	recipe := &Recipe{
		Name:     "test.multi",
		Verb:     "GET",
		Endpoint: "/repos/{owner}/{repo}/pulls",
		TargetURL: "https://api.github.com/repos/{owner}/{repo}/pulls",
		PathParams: []RecipeParam{
			{Name: "owner", Description: "Repo owner", Required: true, Type: "string"},
			{Name: "repo", Description: "Repo name", Required: true, Type: "string"},
		},
	}

	ep, url, _, err := ResolveRecipe(recipe, map[string]string{"owner": "corpo", "repo": "qntm"})
	if err != nil {
		t.Fatal(err)
	}
	if ep != "/repos/corpo/qntm/pulls" {
		t.Fatalf("endpoint = %q", ep)
	}
	if url != "https://api.github.com/repos/corpo/qntm/pulls" {
		t.Fatalf("targetURL = %q", url)
	}
}

func TestResolveRecipe_QueryParamsWithExistingQueryString(t *testing.T) {
	recipe := &Recipe{
		Name:     "test.existing-qs",
		Verb:     "GET",
		Endpoint: "/api.php",
		TargetURL: "https://example.com/api.php?amount=1",
		QueryParams: []RecipeParam{
			{Name: "category", Description: "Category ID", Required: false, Type: "integer"},
		},
	}

	_, url, _, err := ResolveRecipe(recipe, map[string]string{"category": "9"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(url, "amount=1") {
		t.Fatalf("lost existing query string: %q", url)
	}
	if !strings.Contains(url, "&category=9") {
		t.Fatalf("missing appended query param: %q", url)
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
