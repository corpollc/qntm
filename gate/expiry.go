package gate

import (
	"fmt"
	"time"

	"github.com/corpo/qntm/pkg/types"
)

// ExpiredPayload is the body of a gate.expired notification message, sent when
// a credential's TTL has elapsed.
type ExpiredPayload struct {
	SecretID  string `json:"secret_id"`
	Service   string `json:"service"`
	ExpiredAt string `json:"expired_at"` // RFC3339 timestamp
	Message   string `json:"message"`
}

// checkExpiredCredentials checks all credentials in a conversation for expiry.
// Returns ExpiredPayload entries for newly expired credentials (not previously
// notified). Marks them as notified so subsequent calls don't re-report.
func (gw *Gateway) checkExpiredCredentials(convID types.ConversationID, state *ConversationGateState) []ExpiredPayload {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	if gw.expiryNotified == nil {
		gw.expiryNotified = make(map[string]bool)
	}

	var expired []ExpiredPayload
	convKey := fmt.Sprintf("%x", convID[:4])

	for _, cred := range state.Credentials {
		if !cred.IsExpired() {
			continue
		}

		notifKey := convKey + ":" + cred.Service
		if gw.expiryNotified[notifKey] {
			continue
		}

		expired = append(expired, ExpiredPayload{
			SecretID:  cred.ID,
			Service:   cred.Service,
			ExpiredAt: cred.ExpiresAt.UTC().Format(time.RFC3339),
			Message: fmt.Sprintf("Secret '%s' for service '%s' has expired. Please re-provision.",
				cred.ID, cred.Service),
		})

		gw.expiryNotified[notifKey] = true
	}

	return expired
}
