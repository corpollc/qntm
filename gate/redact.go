package gate

// RedactSecret returns a redacted version of a secret for safe logging.
// Secrets of 4 characters or fewer are fully masked. Longer secrets show
// only the first 2 and last 2 characters.
func RedactSecret(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + "****" + s[len(s)-2:]
}

// zeroBytes overwrites a byte slice with zeros. Used as a best-effort defense
// to clear sensitive data from memory after use. Note: Go strings are immutable
// and backed by separate memory, so converting a string to []byte creates a copy.
// This is still useful when the caller passes the original []byte from decryption.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
