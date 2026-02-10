import React, { useEffect, useState } from 'react';
import {
  Box,
  Button,
  FormControl,
  InputLabel,
  MenuItem,
  Paper,
  Select,
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

type Session = { id: string; addr: string };
type ProcessRow = { pid: string; ppid: string; user: string; name: string };

const ProcessList: React.FC = () => {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [selected, setSelected] = useState('');
  const [processes, setProcesses] = useState<ProcessRow[]>([]);
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

  const fetchProcesses = async () => {
    if (!API_BASE || !selected) {
      setError('Select a session first');
      return;
    }
    setLoading(true);
    setError(null);
    setProcesses([]);
    const headers: HeadersInit = { 'Content-Type': 'application/json' };
    if (OP_TOKEN) headers['X-Op-Token'] = OP_TOKEN;
    try {
      const res = await fetch(`${API_BASE}/op/processlist`, {
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
        try {
          const list = JSON.parse(data.output);
          setProcesses(Array.isArray(list) ? list : []);
        } catch {
          setError('Invalid process list response');
        }
      } else {
        setError(data.error || 'Failed to get process list');
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const killProcess = async (pid: string) => {
    if (!API_BASE || !selected || !window.confirm(`Kill process ${pid}?`)) return;
    const headers: HeadersInit = { 'Content-Type': 'application/json' };
    if (OP_TOKEN) headers['X-Op-Token'] = OP_TOKEN;
    try {
      const res = await fetch(`${API_BASE}/op/prockill`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ session_id: selected, pid }),
      });
      if (res.ok) fetchProcesses();
    } catch (_) {}
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Process List
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
          startIcon={<RefreshIcon />}
          onClick={fetchProcesses}
          disabled={loading || !selected}
        >
          {loading ? 'Loading...' : 'Refresh list'}
        </Button>
      </Paper>
      {error && (
        <Typography color="error" sx={{ mb: 1 }}>
          {error}
        </Typography>
      )}
      <TableContainer component={Paper}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>PID</TableCell>
              <TableCell>PPID</TableCell>
              <TableCell>User</TableCell>
              <TableCell>Name</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {processes.map((p) => (
              <TableRow key={p.pid}>
                <TableCell>{p.pid}</TableCell>
                <TableCell>{p.ppid}</TableCell>
                <TableCell>{p.user}</TableCell>
                <TableCell>{p.name}</TableCell>
                <TableCell align="right">
                  <IconButton size="small" onClick={() => killProcess(p.pid)} title="Kill process">
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

export default ProcessList;
