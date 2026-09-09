package charter

import (
	"encoding/json"
	"errors"
	"strconv"
	"unicode/utf8"

	jcs "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// CanonicalJSON implements RFC 8785. Check Unicode and depth before handing JSON
// to the canonicalizer: encoding/json replaces invalid surrogates with U+FFFD.
func CanonicalJSON(raw []byte) ([]byte, error) {
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return nil, errors.New("invalid UTF-8 JSON")
	}
	depth, inString := 0, false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if !inString {
			switch c {
			case '"':
				inString = true
			case '{', '[':
				depth++
				if depth > 129 {
					return nil, errors.New("JSON nesting exceeds 128 levels")
				}
			case '}', ']':
				depth--
			}
			continue
		}
		if c == '"' {
			inString = false
			continue
		}
		if c != '\\' {
			continue
		}
		i++
		if raw[i] != 'u' {
			continue
		}
		code, _ := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		i += 4
		if code >= 0xdc00 && code <= 0xdfff {
			return nil, errors.New("lone low surrogate")
		}
		if code >= 0xd800 && code <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return nil, errors.New("lone high surrogate")
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return nil, errors.New("invalid surrogate pair")
			}
			i += 6
		}
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	var checkDepth func(any, int) bool
	checkDepth = func(value any, depth int) bool {
		if depth > 128 {
			return false
		}
		switch v := value.(type) {
		case []any:
			for _, child := range v {
				if !checkDepth(child, depth+1) {
					return false
				}
			}
		case map[string]any:
			for _, child := range v {
				if !checkDepth(child, depth+1) {
					return false
				}
			}
		}
		return true
	}
	if !checkDepth(value, 0) {
		return nil, errors.New("JSON nesting exceeds 128 levels")
	}
	// The dependency accepts only objects/arrays at the top level. Wrapping also
	// supports application-defined primitive bodies without changing their bytes.
	wrapped := append(append([]byte{'['}, raw...), ']')
	canonical, err := jcs.Transform(wrapped)
	if err != nil {
		return nil, err
	}
	return canonical[1 : len(canonical)-1], nil
}

func canonicalValue(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return CanonicalJSON(raw)
}
