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
} from '@mui/material';
import { PhotoCamera as ScreenshotIcon } from '@mui/icons-material';

const API_BASE = process.env.REACT_APP_API_URL || '';
const OP_TOKEN = process.env.REACT_APP_OP_TOKEN || '';

type Session = { id: string; addr: string };

const Screenshot: React.FC = () => {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [selected, setSelected] = useState('');
  const [imageB64, setImageB64] = useState<string | null>(null);
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

  const capture = async () => {
    if (!API_BASE || !selected) {
      setError('Select a session first');
      return;
    }
    setLoading(true);
    setError(null);
    setImageB64(null);
    const headers: HeadersInit = { 'Content-Type': 'application/json' };
    if (OP_TOKEN) headers['X-Op-Token'] = OP_TOKEN;
    try {
      const res = await fetch(`${API_BASE}/op/screenshot`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ session_id: selected }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || String(res.status));
        return;
      }
      if (data.status === 'success' && data.output) {
        setImageB64(data.output);
      } else {
        setError(data.error || 'Capture failed');
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Screenshot
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
          startIcon={<ScreenshotIcon />}
          onClick={capture}
          disabled={loading || !selected}
        >
          {loading ? 'Capturing...' : 'Capture'}
        </Button>
      </Paper>
      {error && (
        <Typography color="error" sx={{ mb: 1 }}>
          {error}
        </Typography>
      )}
      {imageB64 && (
        <Paper sx={{ p: 1 }}>
          <img
            src={`data:image/png;base64,${imageB64}`}
            alt="Screenshot"
            style={{ maxWidth: '100%', height: 'auto' }}
          />
        </Paper>
      )}
    </Box>
  );
};

export default Screenshot;
