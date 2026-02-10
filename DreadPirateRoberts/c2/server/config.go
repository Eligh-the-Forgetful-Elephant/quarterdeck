package main

import (
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"log"
)

// configFilePath is the path to config.json; tests may override it.
var configFilePath = "config.json"

type ServerConfig struct {
	Port         int    `json:"port"`
	CertFile     string `json:"cert_file"`
	KeyFile      string `json:"key_file"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	SyncToken string `json:"sync_token"` // optional: require ?k=SyncToken on GET /sync
	OpToken   string `json:"op_token"`   // optional: require X-Op-Token or ?k= on GET/POST /op/*
}

func LoadConfig() *ServerConfig {
	config := &ServerConfig{
		Port:         8443,
		CertFile:     "server.crt",
		KeyFile:      "server.key",
		ClientID:     "default_client",
		ClientSecret: "change_this_secret",
		SyncToken: "",
		OpToken:   "",
	}

	// Try to load from config file
	if data, err := ioutil.ReadFile(configFilePath); err == nil {
		if err := json.Unmarshal(data, config); err != nil {
			log.Printf("Error loading config: %v", err)
		}
	}

	return config
}

func (c *ServerConfig) Save() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(configFilePath, data, 0644)
}

func (c *ServerConfig) GetTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}
