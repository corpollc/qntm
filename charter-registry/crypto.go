package charter

import (
	"bytes"
	"filippo.io/edwards25519"
)

// Match the TypeScript charter profile, independent of QSP messaging's profile.
// Multiplication by eight and its inverse removes torsion; the original point
// must be unchanged and must not be the identity.
func validPublicKey(raw []byte) bool {
	point, err := new(edwards25519.Point).SetBytes(raw)
	if err != nil || !bytes.Equal(point.Bytes(), raw) || point.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false
	}
	var eightBytes [32]byte
	eightBytes[0] = 8
	eight, _ := new(edwards25519.Scalar).SetCanonicalBytes(eightBytes[:])
	inverse := new(edwards25519.Scalar).Invert(eight)
	restored := new(edwards25519.Point).ScalarMult(inverse, new(edwards25519.Point).MultByCofactor(point))
	return restored.Equal(point) == 1
}
