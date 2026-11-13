package auth

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/windoze95/cantinarr-server/internal/httpx"
	"github.com/windoze95/cantinarr-server/internal/secrets"
)

var ErrProvisioningUnavailable = errors.New("identity provisioning is not configured or temporarily unavailable")

const authentikProvisioningKey = "authentik_provisioning_token"

type IdentityProvisioningStatus struct {
	Configured    bool     `json:"configured"`
	AllowedGroups []string `json:"allowed_groups"`
}

type ProvisionIdentityRequest struct {
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Email    string   `json:"email"`
	Groups   []string `json:"groups"`
}

type ProvisionIdentityResponse struct {
	Username       string    `json:"username"`
	RecoveryLink   string    `json:"recovery_link"`
	ConnectLink    string    `json:"connect_link"`
	ConnectExpires time.Time `json:"connect_expires_at"`
}

func (h *Handler) IdentityProvisioningStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	status, err := h.service.IdentityProvisioningStatus()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "could not read provisioning status"})
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (h *Handler) SaveIdentityProvisioningToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if !isSecureContext(r) {
		writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": "open Cantinarr over HTTPS before saving the Authentik API token"})
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 20*1024)).Decode(&req) != nil || strings.TrimSpace(req.Token) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "a non-empty Authentik API token is required"})
		return
	}
	if err := h.service.SaveIdentityProvisioningToken(req.Token); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "could not securely store provisioning credential"})
		return
	}
	writeJSON(w, http.StatusOK, IdentityProvisioningStatus{Configured: true})
}

func (h *Handler) ClearIdentityProvisioningToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if err := h.service.ClearIdentityProvisioningToken(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "could not clear provisioning credential"})
		return
	}
	writeJSON(w, http.StatusOK, IdentityProvisioningStatus{Configured: false})
}

func (h *Handler) ProvisionIdentity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	claims := GetClaims(r.Context())
	if claims == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var req ProvisionIdentityRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	serverURL := h.resolvedExternalURL()
	if serverURL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "server URL is not configured"})
		return
	}
	response, err := h.service.ProvisionIdentity(r.Context(), claims.UserID, req, serverURL)
	if err != nil {
		if errors.Is(err, ErrUserExists) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "that username already has a Cantinarr account; existing users must be explicitly linked"})
			return
		}
		if strings.Contains(err.Error(), "Authentik user was created") {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, response)
}

// IdentityProvisioningStatus never returns the stored API credential.
func (s *Service) IdentityProvisioningStatus() (IdentityProvisioningStatus, error) {
	status := IdentityProvisioningStatus{AllowedGroups: []string{}}
	if cfg, cfgErr := s.oidcConfiguration(); cfgErr == nil {
		status.AllowedGroups = cfg.AllowedGroups
	}
	var encrypted string
	err := s.db.QueryRow("SELECT value FROM settings WHERE key=?", authentikProvisioningKey).Scan(&encrypted)
	if errors.Is(err, sql.ErrNoRows) {
		return status, nil
	}
	if err != nil {
		return IdentityProvisioningStatus{}, ErrAuthUnavailable
	}
	status.Configured = encrypted != "" && secrets.IsEncrypted(encrypted)
	return status, nil
}

// SaveIdentityProvisioningToken stores the Authentik API token encrypted with
// the same host-managed key used for OIDC client secrets. An empty token is not
// accepted here; clearing credentials is a distinct explicit action.
func (s *Service) SaveIdentityProvisioningToken(token string) error {
	token = strings.TrimSpace(token)
	if token == "" || len(token) > 16384 || s.oidcCipher == nil {
		return ErrProvisioningUnavailable
	}
	encrypted, err := s.oidcCipher.Encrypt(token)
	if err != nil {
		return ErrProvisioningUnavailable
	}
	_, err = s.db.Exec(`INSERT INTO settings(key,value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, authentikProvisioningKey, encrypted)
	if err != nil {
		return ErrAuthUnavailable
	}
	return nil
}

func (s *Service) ClearIdentityProvisioningToken() error {
	_, err := s.db.Exec("DELETE FROM settings WHERE key=?", authentikProvisioningKey)
	if err != nil {
		return ErrAuthUnavailable
	}
	return nil
}

func (s *Service) identityProvisioningToken() (string, error) {
	var encrypted string
	if err := s.db.QueryRow("SELECT value FROM settings WHERE key=?", authentikProvisioningKey).Scan(&encrypted); err != nil {
		return "", ErrProvisioningUnavailable
	}
	if s.oidcCipher == nil || !secrets.IsEncrypted(encrypted) {
		return "", ErrProvisioningUnavailable
	}
	token, err := s.oidcCipher.Decrypt(encrypted)
	if err != nil || token == "" {
		return "", ErrProvisioningUnavailable
	}
	return token, nil
}

// ProvisionIdentity creates the IdP user and then a Cantinarr account with an
// OIDC-only connect link. Exact usernames are used only as administrator input;
// existing Cantinarr accounts are rejected, never silently linked.
func (s *Service) ProvisionIdentity(ctx context.Context, actorID int64, req ProvisionIdentityRequest, serverURL string) (*ProvisionIdentityResponse, error) {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	req.Username = strings.TrimSpace(req.Username)
	req.Name = strings.TrimSpace(req.Name)
	req.Email = strings.TrimSpace(req.Email)
	if !validProvisionUsername(req.Username) || req.Name == "" || len(req.Name) > 150 {
		return nil, fmt.Errorf("username and display name are invalid")
	}
	if req.Email != "" {
		address, err := mail.ParseAddress(req.Email)
		if err != nil || address.Address != req.Email || len(req.Email) > 254 {
			return nil, fmt.Errorf("email address is invalid")
		}
	}
	var existing int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE username=?", req.Username).Scan(&existing); err != nil {
		return nil, ErrAuthUnavailable
	}
	if existing != 0 {
		return nil, ErrUserExists
	}
	cfg, err := s.oidcConfiguration()
	if err != nil || !cfg.Enabled || !cfg.Tested {
		return nil, ErrProvisioningUnavailable
	}
	allowedGroups := make(map[string]bool, len(cfg.AllowedGroups))
	for _, group := range cfg.AllowedGroups {
		allowedGroups[group] = true
	}
	for _, group := range req.Groups {
		if !allowedGroups[group] {
			return nil, fmt.Errorf("selected group is not in the OIDC allowed-groups policy")
		}
	}
	if len(cfg.AllowedGroups) > 0 && len(req.Groups) == 0 {
		return nil, fmt.Errorf("select at least one allowed OIDC group for this user")
	}
	token, err := s.identityProvisioningToken()
	if err != nil {
		return nil, err
	}
	endpoint, err := authentikAPIBase(cfg.Issuer)
	if err != nil {
		return nil, ErrProvisioningUnavailable
	}
	var transport http.RoundTripper = httpx.Internal()
	if cfg.UseProxy {
		transport = httpx.External()
	}
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	groupIDs := make([]string, 0, len(req.Groups))
	for _, group := range req.Groups {
		var matches struct {
			Results []struct {
				PK   string `json:"pk"`
				Name string `json:"name"`
			} `json:"results"`
		}
		groupURL := endpoint + "/core/groups/?search=" + url.QueryEscape(group) + "&page_size=100"
		if err = authentikRequest(ctx, client, http.MethodGet, groupURL, token, nil, &matches); err != nil {
			return nil, ErrProvisioningUnavailable
		}
		found := ""
		for _, candidate := range matches.Results {
			if candidate.Name == group {
				found = candidate.PK
				break
			}
		}
		if found == "" {
			return nil, fmt.Errorf("configured Authentik group %q was not found exactly", group)
		}
		groupIDs = append(groupIDs, found)
	}
	createBody := map[string]any{"username": req.Username, "name": req.Name, "is_active": true, "type": "internal", "groups": groupIDs}
	if req.Email != "" {
		createBody["email"] = req.Email
	}
	body, _ := json.Marshal(createBody)
	var created struct {
		PK int64 `json:"pk"`
	}
	if err = authentikRequest(ctx, client, http.MethodPost, endpoint+"/core/users/", token, body, &created); err != nil || created.PK <= 0 {
		return nil, ErrProvisioningUnavailable
	}
	var recovery struct {
		Link string `json:"link"`
	}
	if err = authentikRequest(ctx, client, http.MethodPost, fmt.Sprintf("%s/core/users/%d/recovery/", endpoint, created.PK), token, nil, &recovery); err != nil || !safeRecoveryURL(recovery.Link, endpoint) {
		return nil, fmt.Errorf("Authentik user was created but recovery-link generation failed; inspect that account in Authentik before retrying")
	}
	connect, err := s.CreateOIDCConnectToken(actorID, req.Username, serverURL)
	if err != nil {
		return nil, fmt.Errorf("Authentik user was created but Cantinarr account creation failed: %w", err)
	}
	return &ProvisionIdentityResponse{Username: req.Username, RecoveryLink: recovery.Link, ConnectLink: connect.Link, ConnectExpires: connect.ExpiresAt}, nil
}

func authentikAPIBase(issuer string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil || !oidcURLAllowed(u) || u.Scheme != "https" || u.Host == "" {
		return "", ErrProvisioningUnavailable
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host, "/") + "/api/v3", nil
}

func safeRecoveryURL(link, endpoint string) bool {
	u, err := url.Parse(link)
	base, baseErr := url.Parse(endpoint)
	return err == nil && baseErr == nil && u.Scheme == "https" && u.Host == base.Host && u.User == nil && u.Fragment == ""
}

func authentikRequest(ctx context.Context, client *http.Client, method, endpoint, token string, body []byte, result any) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("Authentik API returned HTTP %d", resp.StatusCode)
	}
	if result == nil {
		_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))
		return err
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(result); err != nil {
		return err
	}
	return nil
}

func validProvisionUsername(username string) bool {
	if username == "" || len(username) > 64 {
		return false
	}
	for i, r := range username {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || (i > 0 && (r == '_' || r == '-' || r == '.')) {
			continue
		}
		return false
	}
	return true
}
