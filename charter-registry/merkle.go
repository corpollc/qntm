package charter

import "encoding/hex"

// RFC 6962 tree shape and domain separation, applied to this protocol's JCS leaves.
func leafHash(data []byte) string { return digest(append([]byte{0}, data...)) }
func nodeHash(left, right string) string {
	l, _ := hex.DecodeString(left)
	r, _ := hex.DecodeString(right)
	return digest(append(append([]byte{1}, l...), r...))
}
func split(size int) int {
	k := 1
	for k*2 < size {
		k *= 2
	}
	return k
}
func treeRoot(leaves []string) string {
	if len(leaves) == 0 {
		return digest(nil)
	}
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := split(len(leaves))
	return nodeHash(treeRoot(leaves[:k]), treeRoot(leaves[k:]))
}
func inclusionPath(leaves []string, index int) []string {
	if len(leaves) == 1 {
		return []string{}
	}
	k := split(len(leaves))
	if index < k {
		return append(inclusionPath(leaves[:k], index), treeRoot(leaves[k:]))
	}
	return append(inclusionPath(leaves[k:], index-k), treeRoot(leaves[:k]))
}
func consistencyPath(leaves []string, oldSize int, complete bool) []string {
	if oldSize == 0 {
		return []string{}
	}
	if oldSize == len(leaves) {
		if complete {
			return []string{}
		}
		return []string{treeRoot(leaves)}
	}
	k := split(len(leaves))
	if oldSize <= k {
		return append(consistencyPath(leaves[:k], oldSize, complete), treeRoot(leaves[k:]))
	}
	return append(consistencyPath(leaves[k:], oldSize-k, false), treeRoot(leaves[:k]))
}
