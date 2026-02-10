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
import { Refresh as RefreshIcon } from '@mui/icons-material';

const API_BASE = process.env.REACT_APP_API_URL || '';
const OP_TOKEN = process.env.REACT_APP_OP_TOKEN || '';

type SessionRecord = {
  id: string;
  addr: string;
  first_seen: string;
  last_seen: string;
};

const SessionHistory: React.FC = () => {
  const [sessions, setSessions] = useState<SessionRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchHistory = async () => {
    if (!API_BASE) {
      setError('Set REACT_APP_API_URL to server base (e.g. https://localhost:8443)');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const headers: HeadersInit = {};
      if (OP_TOKEN) headers['X-Op-Token'] = OP_TOKEN;
      const res = await fetch(`${API_BASE}/op/sessions/history`, { headers });
      if (!res.ok) {
        setError(res.status === 401 ? 'Unauthorized (check op_token)' : `${res.status}`);
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
    fetchHistory();
  }, []);

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
        Session History
      </Typography>
      <Typography variant="body2" color="textSecondary" sx={{ mb: 1 }}>
        Past sessions (last 100). Persisted across server restarts.
      </Typography>
      {error && (
        <Typography color="error" sx={{ mb: 1 }}>
          {error}
        </Typography>
      )}
      <TableContainer component={Paper}>
        <Box display="flex" alignItems="center" gap={1} p={1}>
          <IconButton onClick={fetchHistory} disabled={loading} size="small">
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
              <TableCell>First seen</TableCell>
              <TableCell>Last seen</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {sessions.length === 0 && !loading && (
              <TableRow>
                <TableCell colSpan={4} align="center">
                  <Typography color="textSecondary">
                    No session history yet
                  </Typography>
                </TableCell>
              </TableRow>
            )}
            {sessions.map((s) => (
              <TableRow key={`${s.id}-${s.last_seen}`}>
                <TableCell>{s.id}</TableCell>
                <TableCell>{s.addr || '—'}</TableCell>
                <TableCell>{formatTime(s.first_seen)}</TableCell>
                <TableCell>{formatTime(s.last_seen)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
};

export default SessionHistory;
