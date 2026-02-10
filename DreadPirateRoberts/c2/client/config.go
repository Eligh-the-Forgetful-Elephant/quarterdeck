package main

import (
	"encoding/json"
	"log"
	"os"
)

type Config struct {
	ServerURL    string `json:"server_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	CertFile     string `json:"cert_file"`
}

func LoadConfig() *Config {
	c := &Config{
		ServerURL:    "wss://localhost:8443/live",
		ClientID:     "default_client",
		ClientSecret: "change_this_secret",
		CertFile:     "server.crt",
	}
	if data, err := os.ReadFile("config.json"); err == nil {
		if err := json.Unmarshal(data, c); err != nil {
			log.Printf("Error loading config: %v", err)
		}
	}
	return c
}
