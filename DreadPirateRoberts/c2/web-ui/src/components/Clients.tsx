import React, { useEffect, useState } from 'react';
import {
  Box,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
  IconButton,
} from '@mui/material';
import { Refresh as RefreshIcon, Delete as KillIcon } from '@mui/icons-material';

const API_BASE = process.env.REACT_APP_API_URL || '';
const OP_TOKEN = process.env.REACT_APP_OP_TOKEN || '';

type Session = { id: string; addr: string; platform?: string };

const Clients: React.FC = () => {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const killSession = async (id: string) => {
    if (!API_BASE || !window.confirm(`Drop session ${id}?`)) return;
    const headers: HeadersInit = { 'Content-Type': 'application/json' };
    if (OP_TOKEN) headers['X-Op-Token'] = OP_TOKEN;
    try {
      const res = await fetch(`${API_BASE}/op/kill`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ session_id: id }),
      });
      if (res.ok) fetchSessions();
    } catch (_) {}
  };

  const fetchSessions = async () => {
    if (!API_BASE) {
      setError('Set REACT_APP_API_URL to server base (e.g. https://localhost:8443)');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const headers: HeadersInit = {};
      if (OP_TOKEN) headers['X-Op-Token'] = OP_TOKEN;
      const res = await fetch(`${API_BASE}/op/sessions`, { headers });
      if (!res.ok) {
        setError(res.status === 401 ? 'Unauthorized (check op_token)' : ` ${res.status}`);
        setSessions([]);
        return;
      }
      const data = await res.json();
      setSessions(Array.isArray(data) ? data : []);
    } catch (e) {
      setError(String(e));
      setSessions([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSessions();
    const t = setInterval(fetchSessions, 10000);
    return () => clearInterval(t);
  }, []);

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Connected Clients
      </Typography>
      {error && (
        <Typography color="error" sx={{ mb: 1 }}>
          {error}
        </Typography>
      )}
      <TableContainer component={Paper}>
        <Box display="flex" alignItems="center" gap={1} p={1}>
          <IconButton onClick={fetchSessions} disabled={loading} size="small">
            <RefreshIcon />
          </IconButton>
          <Typography variant="body2" color="textSecondary">
            {loading ? 'Loading...' : `${sessions.length} session(s)`}
          </Typography>
        </Box>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Session ID</TableCell>
              <TableCell>Address</TableCell>
              <TableCell>Platform</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {sessions.length === 0 && !loading && (
              <TableRow>
                <TableCell colSpan={4} align="center">
                  <Typography color="textSecondary">
                    No clients connected
                  </Typography>
                </TableCell>
              </TableRow>
            )}
            {sessions.map((s) => (
              <TableRow key={s.id}>
                <TableCell>{s.id}</TableCell>
                <TableCell>{s.addr}</TableCell>
                <TableCell>{s.platform || '—'}</TableCell>
                <TableCell align="right">
                  <IconButton size="small" onClick={() => killSession(s.id)} title="Drop session">
                    <KillIcon />
                  </IconButton>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
};

export default Clients;
