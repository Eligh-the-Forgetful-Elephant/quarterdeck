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
} from '@mui/material';
import { getConsolePrefs, setConsolePrefs, type ConsoleTheme } from '../utils/consolePrefs';

const API_BASE = process.env.REACT_APP_API_URL || '';
const OP_TOKEN = process.env.REACT_APP_OP_TOKEN || '';

const Settings: React.FC = () => {
  const [consolePrefs, setConsolePrefsState] = useState(() => getConsolePrefs());

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
      </Grid>
    </Box>
  );
};

export default Settings;
