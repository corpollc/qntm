package crypto

import (
	"github.com/fxamacker/cbor/v2"
)

var cborEncMode cbor.EncMode
var cborDecMode cbor.DecMode

func init() {
	em, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	cborEncMode = em

	dm, err := cbor.DecOptions{}.DecMode()
	if err != nil {
		panic(err)
	}
	cborDecMode = dm
}

func cborMarshal(v interface{}) ([]byte, error) {
	return cborEncMode.Marshal(v)
}

func cborUnmarshal(data []byte, v interface{}) error {
	return cborDecMode.Unmarshal(data, v)
}
