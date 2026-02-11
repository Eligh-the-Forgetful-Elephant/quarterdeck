import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Grid,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  InputAdornment,
  Button,
} from '@mui/material';
import { getConsolePrefs, setConsolePrefs, type ConsoleTheme } from '../utils/consolePrefs';

const API_BASE = process.env.REACT_APP_API_URL || '';
const OP_TOKEN = process.env.REACT_APP_OP_TOKEN || '';

const Settings: React.FC = () => {
  const [consolePrefs, setConsolePrefsState] = useState(() => getConsolePrefs());
  const [provisionAlias, setProvisionAlias] = useState('');
  const [provisionResult, setProvisionResult] = useState<{
    alias: string;
    client_id: string;
    client_secret: string;
    provision_str: string;
  } | null>(null);
  const [provisionError, setProvisionError] = useState<string | null>(null);

  useEffect(() => {
    const onPrefsChange = () => setConsolePrefsState(getConsolePrefs());
    window.addEventListener('console-prefs-changed', onPrefsChange);
    return () => window.removeEventListener('console-prefs-changed', onPrefsChange);
  }, []);

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Settings
      </Typography>
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Operator API (read-only)
            </Typography>
            <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
              Configure via environment when building or serving the app. Restart required to apply changes.
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="API URL (REACT_APP_API_URL)"
                  value={API_BASE || '(not set)'}
                  disabled
                  size="small"
                />
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Op token (REACT_APP_OP_TOKEN)"
                  value={OP_TOKEN ? '••••••••' : '(not set)'}
                  disabled
                  size="small"
                />
              </Grid>
            </Grid>
          </Paper>
        </Grid>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Console (terminal) appearance
            </Typography>
            <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
              Font size and theme for the Console page. Changes apply immediately when you open Console.
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  type="number"
                  label="Font size"
                  value={consolePrefs.fontSize}
                  onChange={(e) => {
                    const n = parseInt(e.target.value, 10);
                    if (!Number.isNaN(n) && n >= 10 && n <= 24) setConsolePrefs({ fontSize: n });
                  }}
                  size="small"
                  inputProps={{ min: 10, max: 24, step: 1 }}
                  InputProps={{
                    endAdornment: <InputAdornment position="end">px</InputAdornment>,
                  }}
                />
              </Grid>
              <Grid item xs={12}>
                <FormControl fullWidth size="small">
                  <InputLabel>Theme</InputLabel>
                  <Select
                    label="Theme"
                    value={consolePrefs.theme}
                    onChange={(e) => setConsolePrefs({ theme: e.target.value as ConsoleTheme })}
                  >
                    <MenuItem value="default">Default (dark gray, white text)</MenuItem>
                    <MenuItem value="green">Green (black, green text)</MenuItem>
                    <MenuItem value="amber">Amber (dark, amber text)</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
            </Grid>
          </Paper>
        </Grid>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Provision device
            </Typography>
            <Typography variant="body2" color="textSecondary" sx={{ mb: 2 }}>
              Create a provisioned device (alias). Use the returned client_id and client_secret in your implant config; when it connects, the session will show the alias.
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  size="small"
                  label="Alias"
                  placeholder="e.g. cable1"
                  value={provisionAlias}
                  onChange={(e) => setProvisionAlias(e.target.value)}
                />
              </Grid>
              <Grid item>
                <Button
                  variant="contained"
                  onClick={async () => {
                    if (!API_BASE || !provisionAlias.trim()) return;
                    setProvisionError(null);
                    setProvisionResult(null);
                    const headers: HeadersInit = { 'Content-Type': 'application/json' };
                    if (OP_TOKEN) headers['X-Op-Token'] = OP_TOKEN;
                    try {
                      const res = await fetch(`${API_BASE}/op/provision`, {
                        method: 'POST',
                        headers,
                        body: JSON.stringify({ alias: provisionAlias.trim() }),
                      });
                      const data = await res.json().catch(() => ({}));
                      if (res.ok && data.client_id) {
                        setProvisionResult(data);
                        setProvisionAlias('');
                      } else {
                        setProvisionError(data.error || res.status === 409 ? 'Alias already exists' : `${res.status}`);
                      }
                    } catch (e) {
                      setProvisionError(String(e));
                    }
                  }}
                  disabled={!API_BASE || !provisionAlias.trim()}
                >
                  Provision
                </Button>
              </Grid>
              {provisionError && (
                <Grid item xs={12}>
                  <Typography color="error">{provisionError}</Typography>
                </Grid>
              )}
              {provisionResult && (
                <Grid item xs={12}>
                  <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
                    Copy to device config:
                  </Typography>
                  <TextField
                    fullWidth
                    size="small"
                    multiline
                    minRows={2}
                    value={`client_id=${provisionResult.client_id} client_secret=${provisionResult.client_secret}\n${provisionResult.provision_str}`}
                    InputProps={{ readOnly: true }}
                    sx={{ mt: 0.5 }}
                  />
                </Grid>
              )}
            </Grid>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Settings;
