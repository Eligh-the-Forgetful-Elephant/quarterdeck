package main

import (
	"encoding/json"
	"log"
	"os"
)

// Set via -ldflags "-X main.defaultServerURL=..." when building payload
var (
	defaultServerURL           string
	defaultClientID            string
	defaultClientSecret        string
	defaultCallbackIntervalSec int
	defaultJitterPercent       int
	defaultKillDate            string
	defaultWorkingHoursStart   string
	defaultWorkingHoursEnd     string
)

type Config struct {
	ServerURL           string `json:"server_url"`
	ClientID            string `json:"client_id"`
	ClientSecret        string `json:"client_secret"`
	CertFile            string `json:"cert_file"`
	CallbackIntervalSec int    `json:"callback_interval_sec"` // default 30
	JitterPercent       int    `json:"jitter_percent"`       // 0-100, default 0
	KillDate            string `json:"kill_date"`            // RFC3339 or empty
	WorkingHoursStart   string `json:"working_hours_start"` // e.g. "09:00" or empty
	WorkingHoursEnd     string `json:"working_hours_end"`    // e.g. "17:00" or empty
}

func LoadConfig() *Config {
	c := &Config{
		ServerURL:           "wss://localhost:8443/live",
		ClientID:            "default_client",
		ClientSecret:        "change_this_secret",
		CertFile:            "server.crt",
		CallbackIntervalSec: 30,
		JitterPercent:       0,
		KillDate:            "",
		WorkingHoursStart:   "",
		WorkingHoursEnd:     "",
	}
	if data, err := os.ReadFile("config.json"); err == nil {
		if err := json.Unmarshal(data, c); err != nil {
			log.Printf("Error loading config: %v", err)
		}
	}
	// Apply ldflags-set defaults for any empty field
	if defaultServerURL != "" && c.ServerURL == "" {
		c.ServerURL = defaultServerURL
	}
	if defaultClientID != "" {
		c.ClientID = defaultClientID
	}
	if defaultClientSecret != "" {
		c.ClientSecret = defaultClientSecret
	}
	if defaultCallbackIntervalSec > 0 {
		c.CallbackIntervalSec = defaultCallbackIntervalSec
	}
	if defaultJitterPercent >= 0 && defaultJitterPercent <= 100 {
		c.JitterPercent = defaultJitterPercent
	}
	if defaultKillDate != "" {
		c.KillDate = defaultKillDate
	}
	if defaultWorkingHoursStart != "" {
		c.WorkingHoursStart = defaultWorkingHoursStart
	}
	if defaultWorkingHoursEnd != "" {
		c.WorkingHoursEnd = defaultWorkingHoursEnd
	}
	return c
}
