#!/usr/bin/env python3
"""
Simple HTTP Proxy for SQL Injection Testing
Acts like Burp Suite - intercepts and forwards requests
"""
import http.server
import socketserver
import socket
import sys

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    TARGET_HOST = '192.168.205.121'
    TARGET_PORT = 80
    
    def do_GET(self):
        self.proxy_request()
    
    def do_POST(self):
        self.proxy_request()
    
    def proxy_request(self):
        # Get request data
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else None
        
        print(f"\n[*] {self.command} {self.path}")
        if post_data:
            print(f"[*] POST data: {post_data[:200].decode('utf-8', errors='ignore')}")
        
        try:
            # Create socket connection to target
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((self.TARGET_HOST, self.TARGET_PORT))
            
            # Build HTTP request
            http_request = f"{self.command} {self.path} HTTP/1.1\r\n"
            http_request += f"Host: {self.TARGET_HOST}\r\n"
            
            # Copy headers
            for header, value in self.headers.items():
                header_lower = header.lower()
                if header_lower not in ['host', 'content-length', 'connection', 'proxy-connection']:
                    http_request += f"{header}: {value}\r\n"
            
            if post_data:
                http_request += f"Content-Length: {len(post_data)}\r\n"
            http_request += "Connection: close\r\n\r\n"
            
            # Send request
            sock.sendall(http_request.encode())
            if post_data:
                sock.sendall(post_data)
            
            # Read response
            response_data = b''
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                except socket.timeout:
                    break
            
            sock.close()
            
            # Parse and forward response
            if response_data:
                # Split headers and body
                parts = response_data.split(b'\r\n\r\n', 1)
                if len(parts) == 2:
                    headers_text = parts[0].decode('utf-8', errors='ignore')
                    body = parts[1]
                    
                    # Parse status line
                    lines = headers_text.split('\r\n')
                    status_line = lines[0]
                    status_code = int(status_line.split()[1])
                    
                    # Send response headers
                    self.send_response(status_code)
                    for line in lines[1:]:
                        if ':' in line:
                            header, value = line.split(':', 1)
                            header_lower = header.strip().lower()
                            if header_lower not in ['connection', 'transfer-encoding', 'content-encoding']:
                                self.send_header(header.strip(), value.strip())
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    
                    # Send body
                    self.wfile.write(body)
                    
                    print(f"[+] Response: {status_code} ({len(body)} bytes)")
                else:
                    # Send raw response if parsing fails
                    self.wfile.write(response_data)
                    print(f"[+] Response: {len(response_data)} bytes (raw)")
            else:
                self.send_error(502, "No response from target")
                
        except socket.timeout:
            print("[-] Connection timeout")
            self.send_error(504, "Gateway Timeout")
        except Exception as e:
            print(f"[-] Error: {e}")
            import traceback
            traceback.print_exc()
            self.send_error(502, f"Proxy Error: {e}")
    
    def log_message(self, format, *args):
        pass

if __name__ == '__main__':
    PORT = 8888
    print(f"[*] Starting HTTP Proxy on port {PORT}")
    print(f"[*] Configure tools to use: http://127.0.0.1:{PORT}")
    print(f"[*] Forwarding to: {ProxyHandler.TARGET_HOST}:{ProxyHandler.TARGET_PORT}")
    print("[*] Press Ctrl+C to stop\n")
    
    # Allow reuse of address
    socketserver.TCPServer.allow_reuse_address = True
    
    with socketserver.TCPServer(("", PORT), ProxyHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Proxy stopped")
