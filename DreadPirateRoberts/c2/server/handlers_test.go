package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func setupTestConfig(t *testing.T, opToken string) func() {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfg := &ServerConfig{
		Port:         8443,
		ClientID:     "test",
		ClientSecret: "secret",
		OpToken:      opToken,
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	old := configFilePath
	configFilePath = path
	return func() { configFilePath = old }
}

func TestHandleOpSessions_EmptyList(t *testing.T) {
	cleanup := setupTestConfig(t, "")
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/op/sessions", nil)
	rec := httptest.NewRecorder()
	corsOp(handleOpSessions)(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	var list []struct{ ID string }
	if err := json.NewDecoder(rec.Body).Decode(&list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected empty list, got %v", list)
	}
}

func TestHandleOpSessions_UnauthorizedWhenTokenRequired(t *testing.T) {
	cleanup := setupTestConfig(t, "required-token")
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/op/sessions", nil)
	rec := httptest.NewRecorder()
	corsOp(handleOpSessions)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestHandleOpSessions_AuthorizedWithHeader(t *testing.T) {
	cleanup := setupTestConfig(t, "required-token")
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/op/sessions", nil)
	req.Header.Set("X-Op-Token", "required-token")
	rec := httptest.NewRecorder()
	corsOp(handleOpSessions)(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestHandleOpSessions_AuthorizedWithQuery(t *testing.T) {
	cleanup := setupTestConfig(t, "required-token")
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/op/sessions?k=required-token", nil)
	rec := httptest.NewRecorder()
	corsOp(handleOpSessions)(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestHandleOpSessions_MethodNotAllowed(t *testing.T) {
	cleanup := setupTestConfig(t, "")
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/op/sessions", nil)
	rec := httptest.NewRecorder()
	corsOp(handleOpSessions)(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleOpHealth(t *testing.T) {
	cleanup := setupTestConfig(t, "")
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/op/health", nil)
	rec := httptest.NewRecorder()
	corsOp(handleOpHealth)(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	var out map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["ok"] != true {
		t.Errorf("expected ok true, got %v", out["ok"])
	}
	if _, has := out["sessions"]; !has {
		t.Errorf("expected sessions key")
	}
}

func TestHandleOpExec_BadRequest_NoBody(t *testing.T) {
	cleanup := setupTestConfig(t, "")
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost, "/op/exec", nil)
	rec := httptest.NewRecorder()
	corsOp(handleOpExec)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleOpExec_BadRequest_MissingSessionID(t *testing.T) {
	cleanup := setupTestConfig(t, "")
	defer cleanup()

	body := []byte(`{"command": "whoami"}`)
	req := httptest.NewRequest(http.MethodPost, "/op/exec", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	corsOp(handleOpExec)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleOpExec_BadRequest_MissingCommand(t *testing.T) {
	cleanup := setupTestConfig(t, "")
	defer cleanup()

	body := []byte(`{"session_id": "abc123"}`)
	req := httptest.NewRequest(http.MethodPost, "/op/exec", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	corsOp(handleOpExec)(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleOpExec_NotFound(t *testing.T) {
	cleanup := setupTestConfig(t, "")
	defer cleanup()

	body := []byte(`{"session_id": "nonexistent", "command": "whoami"}`)
	req := httptest.NewRequest(http.MethodPost, "/op/exec", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	corsOp(handleOpExec)(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestHandleOpExec_MethodNotAllowed(t *testing.T) {
	cleanup := setupTestConfig(t, "")
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/op/exec", nil)
	rec := httptest.NewRecorder()
	corsOp(handleOpExec)(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleOpSessionsHistory_Empty(t *testing.T) {
	cleanup := setupTestConfig(t, "")
	defer cleanup()
	// Use a path that does not exist so handler returns []
	oldLog := sessionLogFile
	sessionLogFile = filepath.Join(t.TempDir(), "nolog.jsonl")
	defer func() { sessionLogFile = oldLog }()

	req := httptest.NewRequest(http.MethodGet, "/op/sessions/history", nil)
	rec := httptest.NewRecorder()
	corsOp(handleOpSessionsHistory)(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	var list []interface{}
	if err := json.NewDecoder(rec.Body).Decode(&list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected empty list, got %v", list)
	}
}

func TestHandleOpSessionsHistory_UnauthorizedWhenTokenRequired(t *testing.T) {
	cleanup := setupTestConfig(t, "secret")
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/op/sessions/history", nil)
	rec := httptest.NewRecorder()
	corsOp(handleOpSessionsHistory)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}
