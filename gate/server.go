package gate

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// Server is the qntm-gate HTTP server.
type Server struct {
	OrgStore   *OrgStore
	AuthStore  *AuthStore
	AdminToken string // required for admin endpoints; empty = no auth (testing only)
	mux        *http.ServeMux
}

// NewServer creates a new gate server with in-memory stores.
func NewServer() *Server {
	return NewServerWithToken("")
}

// NewServerWithToken creates a gate server requiring the given admin token for admin endpoints.
func NewServerWithToken(adminToken string) *Server {
	orgStore := NewOrgStore()
	authStore := NewAuthStore(orgStore)

	s := &Server{
		OrgStore:   orgStore,
		AuthStore:  authStore,
		AdminToken: adminToken,
		mux:        http.NewServeMux(),
	}
	s.routes()
	return s
}

// requireAdmin checks the Authorization header for a valid admin bearer token.
// Returns true if authorized, false if rejected (and writes the error response).
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.AdminToken == "" {
		return true // no token configured (testing mode)
	}
	auth := r.Header.Get("Authorization")
	expected := "Bearer " + s.AdminToken
	if auth != expected {
		writeErr(w, http.StatusUnauthorized, "admin token required")
		return false
	}
	return true
}

func (s *Server) routes() {
	s.mux.HandleFunc("/v1/orgs", s.handleCreateOrg)
	s.mux.HandleFunc("/v1/orgs/", s.handleOrgs)
	s.mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL.Path)
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleCreateOrg(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}

	var req struct {
		ID      string          `json:"id"`
		Signers []Signer        `json:"signers"`
		Rules   []ThresholdRule `json:"rules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	o := &Org{ID: req.ID, Signers: req.Signers, Rules: req.Rules}
	if err := s.OrgStore.Create(o); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, o)
}

func (s *Server) handleOrgs(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/orgs/")
	parts := strings.SplitN(path, "/", 4)

	if len(parts) < 1 || parts[0] == "" {
		writeErr(w, http.StatusNotFound, "org_id required")
		return
	}

	orgID := parts[0]

	if len(parts) >= 2 && parts[1] == "credentials" {
		s.handleCredentials(w, r, orgID)
		return
	}

	if len(parts) >= 2 && parts[1] == "requests" {
		if len(parts) == 2 {
			s.handleSubmitRequest(w, r, orgID)
			return
		}
		requestID := parts[2]
		if len(parts) == 4 && parts[3] == "approve" {
			s.handleApprove(w, r, orgID, requestID)
			return
		}
		if len(parts) == 4 && parts[3] == "execute" {
			s.handleExecute(w, r, orgID, requestID)
			return
		}
		s.handleGetRequest(w, r, orgID, requestID)
		return
	}

	if len(parts) == 1 {
		o, err := s.OrgStore.Get(orgID)
		if err != nil {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, o)
		return
	}

	writeErr(w, http.StatusNotFound, "not found")
}

func (s *Server) handleCredentials(w http.ResponseWriter, r *http.Request, orgID string) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	var cred Credential
	if err := json.NewDecoder(r.Body).Decode(&cred); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if err := s.OrgStore.AddCredential(orgID, &cred); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "credential added", "id": cred.ID})
}

func (s *Server) handleSubmitRequest(w http.ResponseWriter, r *http.Request, orgID string) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req SubmitRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	authReq, err := s.AuthStore.Submit(orgID, &req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// Auto-execute if threshold met (e.g. 1-of-N)
	if authReq.Status == StatusApproved {
		executed, err := s.AuthStore.Execute(orgID, authReq.RequestID)
		if err != nil {
			writeJSON(w, http.StatusOK, authReq)
			return
		}
		writeJSON(w, http.StatusOK, executed)
		return
	}

	writeJSON(w, http.StatusAccepted, authReq)
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request, orgID, requestID string) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req ApproveRequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	authReq, err := s.AuthStore.Approve(orgID, requestID, &req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// Auto-execute if threshold now met
	if authReq.Status == StatusApproved {
		executed, err := s.AuthStore.Execute(orgID, requestID)
		if err != nil {
			writeJSON(w, http.StatusOK, authReq)
			return
		}
		writeJSON(w, http.StatusOK, executed)
		return
	}

	writeJSON(w, http.StatusOK, authReq)
}

func (s *Server) handleExecute(w http.ResponseWriter, r *http.Request, orgID, requestID string) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	authReq, err := s.AuthStore.Execute(orgID, requestID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, authReq)
}

func (s *Server) handleGetRequest(w http.ResponseWriter, r *http.Request, orgID, requestID string) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	authReq, err := s.AuthStore.Get(orgID, requestID)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, authReq)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": fmt.Sprintf("%s", msg)})
}
