package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestLoadConfig_NoFile(t *testing.T) {
	old := configFilePath
	defer func() { configFilePath = old }()

	dir := t.TempDir()
	configFilePath = filepath.Join(dir, "config.json") // file does not exist

	cfg := LoadConfig()
	if cfg.Port != 8443 {
		t.Errorf("expected Port 8443, got %d", cfg.Port)
	}
	if cfg.ClientID != "default_client" {
		t.Errorf("expected ClientID default_client, got %s", cfg.ClientID)
	}
	if cfg.OpToken != "" {
		t.Errorf("expected empty OpToken, got %q", cfg.OpToken)
	}
}

func TestSaveRoundTrip(t *testing.T) {
	old := configFilePath
	defer func() { configFilePath = old }()

	dir := t.TempDir()
	configFilePath = filepath.Join(dir, "config.json")

	cfg := &ServerConfig{
		Port:         9443,
		CertFile:     "test.crt",
		KeyFile:     "test.key",
		ClientID:     "test_client",
		ClientSecret: "test_secret",
		SyncToken:    "sync",
		OpToken:      "op",
	}
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded := LoadConfig()
	if !reflect.DeepEqual(loaded, cfg) {
		t.Errorf("round-trip mismatch: got %+v", loaded)
	}
}

func TestLoadConfig_FromFile(t *testing.T) {
	old := configFilePath
	defer func() { configFilePath = old }()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	configFilePath = path

	data, _ := json.MarshalIndent(&ServerConfig{
		Port:     9999,
		OpToken:  "from_file",
	}, "", "  ")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg := LoadConfig()
	if cfg.Port != 9999 {
		t.Errorf("expected Port 9999, got %d", cfg.Port)
	}
	if cfg.OpToken != "from_file" {
		t.Errorf("expected OpToken from_file, got %q", cfg.OpToken)
	}
}

func TestGetTLSConfig_MissingFiles(t *testing.T) {
	cfg := &ServerConfig{
		CertFile: filepath.Join(t.TempDir(), "missing.crt"),
		KeyFile:  filepath.Join(t.TempDir(), "missing.key"),
	}
	_, err := cfg.GetTLSConfig()
	if err == nil {
		t.Error("expected error when cert/key files do not exist")
	}
}

func TestGetTLSConfig_ValidCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	cfg := &ServerConfig{CertFile: certPath, KeyFile: keyPath}
	tlsCfg, err := cfg.GetTLSConfig()
	if err != nil {
		t.Fatalf("GetTLSConfig: %v", err)
	}
	if tlsCfg == nil || len(tlsCfg.Certificates) == 0 {
		t.Error("expected non-nil TLS config with at least one certificate")
	}
}
