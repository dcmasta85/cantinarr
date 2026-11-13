package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/windoze95/cantinarr-server/internal/secrets"
)

func TestIdentityProvisioningTokenIsEncryptedAndWriteOnly(t *testing.T) {
	s := setupTestService(t)
	cipher, err := secrets.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	s.SetOIDCCipher(cipher)
	if err := s.SaveIdentityProvisioningToken("authentik-secret-sentinel"); err != nil {
		t.Fatal(err)
	}
	status, err := s.IdentityProvisioningStatus()
	if err != nil || !status.Configured {
		t.Fatalf("status = %+v, err = %v", status, err)
	}
	var stored string
	if err := s.db.QueryRow("SELECT value FROM settings WHERE key=?", authentikProvisioningKey).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, "authentik-secret-sentinel") || !secrets.IsEncrypted(stored) {
		t.Fatal("provisioning token was stored in plaintext")
	}
	decrypted, err := cipher.Decrypt(stored)
	if err != nil || decrypted != "authentik-secret-sentinel" {
		t.Fatalf("decrypt token: value=%q err=%v", decrypted, err)
	}
	if err := s.ClearIdentityProvisioningToken(); err != nil {
		t.Fatal(err)
	}
	status, err = s.IdentityProvisioningStatus()
	if err != nil || status.Configured {
		t.Fatalf("cleared status = %+v, err = %v", status, err)
	}
}

func TestAuthentikRequestUsesBearerAndDecodesBoundedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("authorization header = %q", r.Header.Get("Authorization"))
		}
		if r.Method != http.MethodPost || r.URL.Path != "/api/v3/core/users/" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{"pk": 42})
	}))
	defer server.Close()
	var got struct {
		PK int `json:"pk"`
	}
	err := authentikRequest(context.Background(), server.Client(), http.MethodPost, server.URL+"/api/v3/core/users/", "test-token", []byte(`{"username":"test"}`), &got)
	if err != nil || got.PK != 42 {
		t.Fatalf("response = %+v, err = %v", got, err)
	}
}

func TestProvisioningURLAndUsernameValidation(t *testing.T) {
	if _, err := authentikAPIBase("http://auth.example.com/application/o/cantinarr/"); err == nil {
		t.Fatal("plaintext Authentik API host accepted")
	}
	base, err := authentikAPIBase("https://auth.example.com/application/o/cantinarr/")
	if err != nil || base != "https://auth.example.com/api/v3" {
		t.Fatalf("API base = %q, err = %v", base, err)
	}
	for _, username := range []string{"alice", "alice.smith", "a-1", "a_b"} {
		if !validProvisionUsername(username) {
			t.Errorf("valid username rejected: %q", username)
		}
	}
	for _, username := range []string{"", "_alice", "alice smith", "a@b", "../admin"} {
		if validProvisionUsername(username) {
			t.Errorf("invalid username accepted: %q", username)
		}
	}
}
