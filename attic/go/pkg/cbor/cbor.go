package cbor

import (
	"github.com/fxamacker/cbor/v2"
)

var (
	// CanonicalMode creates a CBOR encoding mode that produces canonical (deterministic) output
	CanonicalMode cbor.EncMode
	// CanonicalDecMode creates a CBOR decoding mode for canonical data
	CanonicalDecMode cbor.DecMode
)

func init() {
	// Create canonical encoding mode as per CBOR RFC 8949 Section 4.2.1
	encOpts := cbor.CanonicalEncOptions()
	encOpts.Sort = cbor.SortCanonical
	
	var err error
	CanonicalMode, err = encOpts.EncMode()
	if err != nil {
		panic("failed to create canonical CBOR encoding mode: " + err.Error())
	}
	
	// Create matching decode mode
	decOpts := cbor.DecOptions{
		DupMapKey: cbor.DupMapKeyEnforcedAPF,
	}
	CanonicalDecMode, err = decOpts.DecMode()
	if err != nil {
		panic("failed to create canonical CBOR decoding mode: " + err.Error())
	}
}

// MarshalCanonical encodes data using canonical CBOR
func MarshalCanonical(v interface{}) ([]byte, error) {
	return CanonicalMode.Marshal(v)
}

// UnmarshalCanonical decodes canonical CBOR data
func UnmarshalCanonical(data []byte, v interface{}) error {
	return CanonicalDecMode.Unmarshal(data, v)
}