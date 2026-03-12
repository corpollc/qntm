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
