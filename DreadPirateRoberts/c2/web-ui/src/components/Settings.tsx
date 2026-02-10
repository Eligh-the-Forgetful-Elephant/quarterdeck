import React from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Grid,
} from '@mui/material';

const API_BASE = process.env.REACT_APP_API_URL || '';
const OP_TOKEN = process.env.REACT_APP_OP_TOKEN || '';

const Settings: React.FC = () => {
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
      </Grid>
    </Box>
  );
};

export default Settings;
