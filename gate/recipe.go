package gate

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/corpo/qntm/gate/recipes"
)

// Profile defines a known API service — its host, available endpoints,
// and whether authentication is required.
type Profile struct {
	Service     string            `json:"service"`
	Description string            `json:"description"`
	BaseURL     string            `json:"base_url"`
	Hosts       []string          `json:"hosts"`       // allowed hosts for this service
	AuthRequired bool             `json:"auth_required"`
	Endpoints   []EndpointSpec    `json:"endpoints"`
}

// EndpointSpec defines one allowed endpoint on a service.
type EndpointSpec struct {
	Path        string `json:"path"`         // e.g. "/v0/topstories.json"
	Verb        string `json:"verb"`         // e.g. "GET"
	Description string `json:"description"`
	RiskTier    string `json:"risk_tier"`    // "read", "write", "admin"
}

// Recipe is a named workflow template that binds a profile endpoint
// to a parameter schema and suggested threshold.
type Recipe struct {
	Name        string          `json:"name"`         // e.g. "hn.top-stories"
	Description string          `json:"description"`
	Service     string          `json:"service"`      // profile service name
	Verb        string          `json:"verb"`
	Endpoint    string          `json:"endpoint"`     // path on the service
	TargetURL   string          `json:"target_url"`   // full URL to call
	RiskTier    string          `json:"risk_tier"`
	Threshold   int             `json:"threshold"`    // suggested M
	Params      json.RawMessage `json:"params,omitempty"` // JSON schema for parameters
	ContentType string          `json:"content_type,omitempty"` // expected response content type
}

// RecipeCatalog holds a set of profiles and recipes.
type RecipeCatalog struct {
	Profiles map[string]*Profile `json:"profiles"`
	Recipes  map[string]*Recipe  `json:"recipes"`
}

// NewRecipeCatalog creates an empty catalog.
func NewRecipeCatalog() *RecipeCatalog {
	return &RecipeCatalog{
		Profiles: make(map[string]*Profile),
		Recipes:  make(map[string]*Recipe),
	}
}

// AddProfile registers a service profile.
func (c *RecipeCatalog) AddProfile(p *Profile) {
	c.Profiles[p.Service] = p
}

// AddRecipe registers a recipe.
func (c *RecipeCatalog) AddRecipe(r *Recipe) {
	c.Recipes[r.Name] = r
}

// GetRecipe returns a recipe by name.
func (c *RecipeCatalog) GetRecipe(name string) (*Recipe, error) {
	r, ok := c.Recipes[name]
	if !ok {
		return nil, fmt.Errorf("recipe %q not found", name)
	}
	return r, nil
}

// ValidateRecipe checks that a recipe's service and endpoint exist in a profile.
func (c *RecipeCatalog) ValidateRecipe(name string) error {
	r, err := c.GetRecipe(name)
	if err != nil {
		return err
	}
	p, ok := c.Profiles[r.Service]
	if !ok {
		return fmt.Errorf("recipe %q references unknown service %q", name, r.Service)
	}
	for _, ep := range p.Endpoints {
		if ep.Path == r.Endpoint && ep.Verb == r.Verb {
			return nil
		}
	}
	return fmt.Errorf("recipe %q endpoint %s %s not in profile %q", name, r.Verb, r.Endpoint, r.Service)
}

// ListRecipes returns all recipe names sorted.
func (c *RecipeCatalog) ListRecipes() []string {
	names := make([]string, 0, len(c.Recipes))
	for name := range c.Recipes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// LoadCatalogFromFile loads a catalog from a JSON file.
func LoadCatalogFromFile(path string) (*RecipeCatalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	var cat RecipeCatalog
	if err := json.Unmarshal(data, &cat); err != nil {
		return nil, fmt.Errorf("parse catalog: %w", err)
	}
	return &cat, nil
}

// SaveCatalogToFile writes a catalog to a JSON file.
func (c *RecipeCatalog) SaveCatalogToFile(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal catalog: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// LoadStarterCatalog loads the built-in starter recipe catalog.
func LoadStarterCatalog() (*RecipeCatalog, error) {
	data, err := recipes.FS.ReadFile("starter.json")
	if err != nil {
		return nil, fmt.Errorf("read embedded starter catalog: %w", err)
	}
	var cat RecipeCatalog
	if err := json.Unmarshal(data, &cat); err != nil {
		return nil, fmt.Errorf("parse starter catalog: %w", err)
	}
	return &cat, nil
}
