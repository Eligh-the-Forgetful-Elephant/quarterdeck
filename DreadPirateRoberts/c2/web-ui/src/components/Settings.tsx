import React from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Switch,
  FormControlLabel,
  Button,
  Grid,
} from '@mui/material';
import { Save as SaveIcon } from '@mui/icons-material';

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
              Server Configuration
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Server Port"
                  value="8443"
                  disabled
                />
              </Grid>
              <Grid item xs={12}>
                <FormControlLabel
                  control={<Switch checked disabled />}
                  label="Enable TLS"
                />
              </Grid>
            </Grid>
          </Paper>
        </Grid>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Client Configuration
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Heartbeat Interval (seconds)"
                  value="30"
                  disabled
                />
              </Grid>
              <Grid item xs={12}>
                <FormControlLabel
                  control={<Switch checked disabled />}
                  label="Enable Stealth Mode"
                />
              </Grid>
            </Grid>
          </Paper>
        </Grid>
      </Grid>
      <Box sx={{ mt: 3, display: 'flex', justifyContent: 'flex-end' }}>
        <Button
          variant="contained"
          color="primary"
          startIcon={<SaveIcon />}
          disabled
        >
          Save Settings
        </Button>
      </Box>
    </Box>
  );
};

export default Settings; 