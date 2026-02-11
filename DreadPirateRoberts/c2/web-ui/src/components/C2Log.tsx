import React, { useCallback, useEffect, useState } from 'react';
import {
  Box,
  Button,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
} from '@mui/material';
import { Refresh as RefreshIcon } from '@mui/icons-material';

const API_BASE = process.env.REACT_APP_API_URL || '';
const OP_TOKEN = process.env.REACT_APP_OP_TOKEN || '';

type LogRow = { ts: string; session_id: string; direction: string; detail: string };
type Session = { id: string; addr: string; alias?: string };

const C2Log: React.FC = () => {
  const [rows, setRows] = useState<LogRow[]>([]);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [sessionFilter, setSessionFilter] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchLog = useCallback(() => {
    if (!API_BASE) {
      setError('Set REACT_APP_API_URL.');
      return;
    }
    setLoading(true);
    setError(null);
    const headers: HeadersInit = {};
    if (OP_TOKEN) headers['X-Op-Token'] = OP_TOKEN;
    let url = `${API_BASE}/op/c2log?limit=200`;
    if (sessionFilter) url += `&session_id=${encodeURIComponent(sessionFilter)}`;
    fetch(url, { headers })
      .then((res) => (res.ok ? res.json() : []))
      .then((data) => setRows(Array.isArray(data) ? data : []))
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, [sessionFilter]);

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
    fetchLog();
  }, [fetchLog]);

  const formatTime = (s: string) => {
    if (!s) return '—';
    try {
      const d = new Date(s);
      return Number.isNaN(d.getTime()) ? s : d.toLocaleString();
    } catch {
      return s;
    }
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        C2 traffic log
      </Typography>
      <Typography variant="body2" color="textSecondary" sx={{ mb: 1 }}>
        Commands sent (out) and responses (in). Filter by session or refresh.
      </Typography>
      {error && (
        <Typography color="error" sx={{ mb: 1 }}>
          {error}
        </Typography>
      )}
      <Box sx={{ mb: 2, display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
        <FormControl size="small" sx={{ minWidth: 200 }}>
          <InputLabel>Session</InputLabel>
          <Select
            label="Session"
            value={sessionFilter}
            onChange={(e) => setSessionFilter(e.target.value)}
          >
            <MenuItem value="">All</MenuItem>
            {sessions.map((s) => (
              <MenuItem key={s.id} value={s.id}>
                {s.alias ? `${s.alias} · ` : ''}{s.id}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <Button
          variant="contained"
          startIcon={<RefreshIcon />}
          onClick={fetchLog}
          disabled={loading || !API_BASE}
        >
          {loading ? 'Loading...' : 'Refresh'}
        </Button>
      </Box>
      <TableContainer component={Paper}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Time</TableCell>
              <TableCell>Session</TableCell>
              <TableCell>Direction</TableCell>
              <TableCell>Detail</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {rows.length === 0 && !loading && (
              <TableRow>
                <TableCell colSpan={4} align="center">
                  <Typography color="textSecondary">No log entries</Typography>
                </TableCell>
              </TableRow>
            )}
            {[...rows].reverse().map((r, i) => (
              <TableRow key={`${r.ts}-${i}`}>
                <TableCell>{formatTime(r.ts)}</TableCell>
                <TableCell>{r.session_id || '—'}</TableCell>
                <TableCell>{r.direction}</TableCell>
                <TableCell sx={{ maxWidth: 400, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {r.detail || '—'}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
};

export default C2Log;
