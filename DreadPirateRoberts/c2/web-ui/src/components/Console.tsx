import React, { useEffect, useState, useRef } from 'react';
import {
  Box,
  Paper,
  TextField,
  Typography,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Grid,
  IconButton,
} from '@mui/material';
import { Send as SendIcon, VpnKey as CredsIcon, PlaylistAdd as QueueAddIcon, Clear as ClearIcon } from '@mui/icons-material';
import { getConsolePrefs, getTerminalStyles } from '../utils/consolePrefs';

const API_BASE = process.env.REACT_APP_API_URL || '';
const OP_TOKEN = process.env.REACT_APP_OP_TOKEN || '';

type Session = { id: string; addr: string; alias?: string };

const Console: React.FC = () => {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [command, setCommand] = useState('');
  const [log, setLog] = useState<string[]>([]);
  const logEndRef = useRef<HTMLDivElement>(null);
  const [prefs, setPrefs] = useState(() => getConsolePrefs());
  const [queue, setQueue] = useState<string[]>([]);

  useEffect(() => {
    const onPrefsChange = () => setPrefs(getConsolePrefs());
    window.addEventListener('console-prefs-changed', onPrefsChange);
    return () => window.removeEventListener('console-prefs-changed', onPrefsChange);
  }, []);

  const terminalStyles = getTerminalStyles(prefs);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [log]);

  useEffect(() => {
    if (!API_BASE) return;
    const headers: HeadersInit = {};
    if (OP_TOKEN) headers['X-Op-Token'] = OP_TOKEN;
    fetch(`${API_BASE}/op/sessions`, { headers })
      .then((res) => (res.ok ? res.json() : []))
      .then((data) => setSessions(Array.isArray(data) ? data : []))
      .catch(() => setSessions([]));
  }, []);

  useEffect(() => {
    if (!API_BASE || !selectedId) {
      setQueue([]);
      return;
    }
    const headers: HeadersInit = {};
    if (OP_TOKEN) headers['X-Op-Token'] = OP_TOKEN;
    fetch(`${API_BASE}/op/queue?session_id=${encodeURIComponent(selectedId)}`, { headers })
      .then((res) => (res.ok ? res.json() : { queue: [] }))
      .then((data) => setQueue(Array.isArray(data.queue) ? data.queue : []))
      .catch(() => setQueue([]));
  }, [selectedId]);

  const handleSend = async () => {
    if (!selectedId || !command.trim() || !API_BASE) return;
    const cmd = command.trim();
    setCommand('');
    setLog((prev) => [...prev, `$ ${cmd}`]);
    const headers: HeadersInit = { 'Content-Type': 'application/json' };
    if (OP_TOKEN) headers['X-Op-Token'] = OP_TOKEN;
    try {
      const res = await fetch(`${API_BASE}/op/exec`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ session_id: selectedId, command: cmd }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.output !== undefined) {
        setLog((prev) => [...prev, data.output || '(no output)', data.error || '']);
      } else {
        setLog((prev) => [...prev, `Error: ${res.status} ${data.error || res.statusText || ''}`]);
      }
    } catch (e) {
      setLog((prev) => [...prev, `Error: ${e}`]);
    }
  };

  const runCreds = async () => {
    if (!selectedId || !API_BASE) return;
    setLog((prev) => [...prev, '$ Run creds (stub)']);
    const headers: HeadersInit = { 'Content-Type': 'application/json' };
    if (OP_TOKEN) headers['X-Op-Token'] = OP_TOKEN;
    try {
      const res = await fetch(`${API_BASE}/op/creds`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ session_id: selectedId }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && data.output !== undefined) {
        setLog((prev) => [...prev, data.output || '(no output)', data.error || '']);
      } else {
        setLog((prev) => [...prev, `Error: ${res.status} ${data.error || ''}`]);
      }
    } catch (e) {
      setLog((prev) => [...prev, `Error: ${e}`]);
    }
  };

  const addToQueue = async () => {
    if (!selectedId || !command.trim() || !API_BASE) return;
    const cmd = command.trim();
    setCommand('');
    const headers: HeadersInit = { 'Content-Type': 'application/json' };
    if (OP_TOKEN) headers['X-Op-Token'] = OP_TOKEN;
    try {
      const res = await fetch(`${API_BASE}/op/queue`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ session_id: selectedId, command: cmd }),
      });
      if (res.ok) {
        setQueue((prev) => [...prev, cmd]);
        setLog((prev) => [...prev, `[queued] ${cmd}`]);
      }
    } catch (_) {}
  };

  const clearQueue = async () => {
    if (!selectedId || !API_BASE) return;
    const headers: HeadersInit = { 'Content-Type': 'application/json' };
    if (OP_TOKEN) headers['X-Op-Token'] = OP_TOKEN;
    try {
      const res = await fetch(`${API_BASE}/op/queue/clear`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ session_id: selectedId }),
      });
      if (res.ok) setQueue([]);
    } catch (_) {}
  };

  const noApi = !API_BASE;

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Console
      </Typography>
      <Grid container spacing={2}>
        <Grid item xs={12}>
          <Paper
            sx={{
              height: '60vh',
              p: 2,
              backgroundColor: terminalStyles.bgcolor,
              color: terminalStyles.color,
              overflowY: 'auto',
              fontFamily: 'monospace',
              fontSize: prefs.fontSize,
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-all',
            }}
          >
            {noApi && (
              <Typography color="textSecondary">
                Set REACT_APP_API_URL to server base (e.g. https://localhost:8443)
              </Typography>
            )}
            {!noApi && log.length === 0 && (
              <Typography color="textSecondary">
                Select a client and enter a command
              </Typography>
            )}
            {log.map((line, i) => (
              <Typography key={i} component="span" sx={{ display: 'block' }}>
                {line}
              </Typography>
            ))}
            <div ref={logEndRef} />
          </Paper>
        </Grid>
        <Grid item xs={12}>
          <Grid container spacing={2} alignItems="center">
            <Grid item xs={12} sm={3}>
              <FormControl fullWidth size="small">
                <InputLabel>Target Client</InputLabel>
                <Select
                  label="Target Client"
                  value={selectedId}
                  onChange={(e) => setSelectedId(e.target.value)}
                  disabled={noApi}
                >
                  <MenuItem value="">No selection</MenuItem>
                  {sessions.map((s) => (
                    <MenuItem key={s.id} value={s.id}>
                      {s.alias ? `${s.alias} · ` : ''}{s.id} ({s.addr})
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm>
              <TextField
                fullWidth
                size="small"
                variant="outlined"
                placeholder="Enter command..."
                value={command}
                onChange={(e) => setCommand(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSend()}
                disabled={noApi || !selectedId}
              />
            </Grid>
            <Grid item>
              <IconButton
                color="primary"
                onClick={handleSend}
                disabled={noApi || !selectedId || !command.trim()}
                title="Send command"
              >
                <SendIcon />
              </IconButton>
              <IconButton
                onClick={addToQueue}
                disabled={noApi || !selectedId || !command.trim()}
                title="Add to queue"
              >
                <QueueAddIcon />
              </IconButton>
              <IconButton
                color="secondary"
                onClick={runCreds}
                disabled={noApi || !selectedId}
                title="Run creds (stub)"
              >
                <CredsIcon />
              </IconButton>
              <IconButton
                onClick={clearQueue}
                disabled={noApi || !selectedId || queue.length === 0}
                title="Clear queue"
              >
                <ClearIcon />
              </IconButton>
            </Grid>
            {queue.length > 0 && (
              <Grid item xs={12}>
                <Typography variant="body2" color="textSecondary">
                  Queue ({queue.length}): {queue.slice(0, 3).join('; ')}{queue.length > 3 ? '…' : ''}
                </Typography>
              </Grid>
            )}
          </Grid>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Console;
