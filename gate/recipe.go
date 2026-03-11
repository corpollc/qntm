package gate

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

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

// RecipeParam defines a single parameter for a recipe.
type RecipeParam struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
	Default     string `json:"default,omitempty"`
	Type        string `json:"type"` // "string", "integer", "boolean"
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
	PathParams  []RecipeParam   `json:"path_params,omitempty"`
	QueryParams []RecipeParam   `json:"query_params,omitempty"`
	BodySchema  json.RawMessage `json:"body_schema,omitempty"`
	BodyExample json.RawMessage `json:"body_example,omitempty"`
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

// placeholderRe matches {param} placeholders in strings.
var placeholderRe = regexp.MustCompile(`\{([^}]+)\}`)

// ResolveRecipe substitutes parameter placeholders in a recipe's endpoint and
// target URL, validates required parameters, and builds a JSON body from args
// when the recipe defines a body schema.
//
// It returns the resolved endpoint, resolved target URL, and body bytes.
func ResolveRecipe(recipe *Recipe, args map[string]string) (endpoint string, targetURL string, body []byte, err error) {
	if args == nil {
		args = map[string]string{}
	}

	// Validate required path params are provided
	for _, p := range recipe.PathParams {
		if p.Required {
			if _, ok := args[p.Name]; !ok {
				if p.Default != "" {
					args[p.Name] = p.Default
				} else {
					return "", "", nil, fmt.Errorf("missing required path parameter %q", p.Name)
				}
			}
		}
	}

	// Validate required query params are provided
	for _, p := range recipe.QueryParams {
		if p.Required {
			if _, ok := args[p.Name]; !ok {
				if p.Default != "" {
					args[p.Name] = p.Default
				} else {
					return "", "", nil, fmt.Errorf("missing required query parameter %q", p.Name)
				}
			}
		}
	}

	// Substitute {param} placeholders in endpoint and target URL
	substitute := func(s string) string {
		return placeholderRe.ReplaceAllStringFunc(s, func(match string) string {
			key := match[1 : len(match)-1]
			if val, ok := args[key]; ok {
				return val
			}
			return match // leave unresolved placeholders as-is
		})
	}

	endpoint = substitute(recipe.Endpoint)
	targetURL = substitute(recipe.TargetURL)

	// Append query params to target URL
	var queryParts []string
	for _, p := range recipe.QueryParams {
		if val, ok := args[p.Name]; ok {
			queryParts = append(queryParts, p.Name+"="+val)
		} else if p.Default != "" {
			queryParts = append(queryParts, p.Name+"="+p.Default)
		}
	}
	if len(queryParts) > 0 {
		sep := "?"
		if strings.Contains(targetURL, "?") {
			sep = "&"
		}
		targetURL = targetURL + sep + strings.Join(queryParts, "&")
	}

	// Build body from body_schema + args for POST/PUT/PATCH
	verb := strings.ToUpper(recipe.Verb)
	if verb == "POST" || verb == "PUT" || verb == "PATCH" {
		if len(recipe.BodySchema) > 0 {
			// Parse the body schema to discover expected fields
			var schema map[string]json.RawMessage
			if err := json.Unmarshal(recipe.BodySchema, &schema); err != nil {
				return "", "", nil, fmt.Errorf("parse body_schema: %w", err)
			}

			// Look for "properties" key (JSON Schema style)
			var fieldNames []string
			if propsRaw, ok := schema["properties"]; ok {
				var props map[string]json.RawMessage
				if err := json.Unmarshal(propsRaw, &props); err == nil {
					for name := range props {
						fieldNames = append(fieldNames, name)
					}
				}
			}

			// Build body object from args matching schema fields
			bodyMap := make(map[string]interface{})
			for _, name := range fieldNames {
				if val, ok := args[name]; ok {
					bodyMap[name] = val
				}
			}

			// Also include any args that match body schema fields
			// even if not discovered via "properties"
			if len(fieldNames) == 0 {
				// Flat schema: treat each top-level key as a field name
				for name := range schema {
					if name == "type" || name == "properties" || name == "required" {
						continue
					}
					if val, ok := args[name]; ok {
						bodyMap[name] = val
					}
				}
			}

			if len(bodyMap) > 0 {
				body, err = json.Marshal(bodyMap)
				if err != nil {
					return "", "", nil, fmt.Errorf("marshal body: %w", err)
				}
			}
		}

		// Validate required body params from body_schema "required" field
		if len(recipe.BodySchema) > 0 {
			var schema map[string]json.RawMessage
			if err := json.Unmarshal(recipe.BodySchema, &schema); err == nil {
				if reqRaw, ok := schema["required"]; ok {
					var required []string
					if err := json.Unmarshal(reqRaw, &required); err == nil {
						for _, name := range required {
							if _, ok := args[name]; !ok {
								return "", "", nil, fmt.Errorf("missing required body parameter %q", name)
							}
						}
					}
				}
			}
		}
	}

	return endpoint, targetURL, body, nil
}
