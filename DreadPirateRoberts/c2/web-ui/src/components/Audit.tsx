import React, { useEffect, useState } from 'react';
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
} from '@mui/material';
import { Refresh as RefreshIcon, Download as ExportIcon } from '@mui/icons-material';

const API_BASE = process.env.REACT_APP_API_URL || '';
const OP_TOKEN = process.env.REACT_APP_OP_TOKEN || '';

type AuditRow = {
  ts: string;
  operator_id: string;
  action: string;
  session_id: string;
  technique_id?: string;
  detail: string;
};

const Audit: React.FC = () => {
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchAudit = async () => {
    if (!API_BASE) {
      setError('Set REACT_APP_API_URL to server base.');
      return;
    }
    setLoading(true);
    setError(null);
    const headers: HeadersInit = {};
    if (OP_TOKEN) headers['X-Op-Token'] = OP_TOKEN;
    try {
      const res = await fetch(`${API_BASE}/op/audit?limit=200`, { headers });
      if (!res.ok) {
        setError(res.status === 401 ? 'Unauthorized' : `${res.status}`);
        setRows([]);
        return;
      }
      const data = await res.json();
      setRows(Array.isArray(data) ? data : []);
    } catch (e) {
      setError(String(e));
      setRows([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAudit();
  }, []);

  const exportCsv = async () => {
    if (!API_BASE) return;
    const headers: HeadersInit = {};
    if (OP_TOKEN) headers['X-Op-Token'] = OP_TOKEN;
    try {
      const res = await fetch(`${API_BASE}/op/audit?limit=1000&format=csv`, { headers });
      if (!res.ok) return;
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'audit.csv';
      a.click();
      URL.revokeObjectURL(url);
    } catch (_) {}
  };

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
        Audit (recent actions)
      </Typography>
      <Typography variant="body2" color="textSecondary" sx={{ mb: 1 }}>
        Operator actions with ATT&amp;CK technique IDs. Export for reporting.
      </Typography>
      {error && (
        <Typography color="error" sx={{ mb: 1 }}>
          {error}
        </Typography>
      )}
      <Box sx={{ mb: 2, display: 'flex', gap: 1 }}>
        <Button
          variant="contained"
          startIcon={<RefreshIcon />}
          onClick={fetchAudit}
          disabled={loading}
        >
          {loading ? 'Loading...' : 'Refresh'}
        </Button>
        <Button
          variant="outlined"
          startIcon={<ExportIcon />}
          onClick={exportCsv}
          disabled={!API_BASE}
        >
          Export report (CSV)
        </Button>
      </Box>
      <TableContainer component={Paper}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Time</TableCell>
              <TableCell>Operator</TableCell>
              <TableCell>Action</TableCell>
              <TableCell>Session</TableCell>
              <TableCell>Technique</TableCell>
              <TableCell>Detail</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {rows.length === 0 && !loading && (
              <TableRow>
                <TableCell colSpan={6} align="center">
                  <Typography color="textSecondary">No audit entries</Typography>
                </TableCell>
              </TableRow>
            )}
            {rows.map((r, i) => (
              <TableRow key={`${r.ts}-${i}`}>
                <TableCell>{formatTime(r.ts)}</TableCell>
                <TableCell>{r.operator_id || '—'}</TableCell>
                <TableCell>{r.action}</TableCell>
                <TableCell>{r.session_id || '—'}</TableCell>
                <TableCell>{r.technique_id || '—'}</TableCell>
                <TableCell sx={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis' }}>
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

export default Audit;
