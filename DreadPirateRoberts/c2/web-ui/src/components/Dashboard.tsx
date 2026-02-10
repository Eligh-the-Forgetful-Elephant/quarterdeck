import React, { useEffect, useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Grid,
  Typography,
  CircularProgress,
} from '@mui/material';

const API_BASE = process.env.REACT_APP_API_URL || '';
const OP_TOKEN = process.env.REACT_APP_OP_TOKEN || '';

type Health = { ok: boolean; sessions: number } | null;

const Dashboard: React.FC = () => {
  const [health, setHealth] = useState<Health>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!API_BASE) {
      setHealth(null);
      setLoading(false);
      return;
    }
    const fetchHealth = async () => {
      try {
        const headers: HeadersInit = {};
        if (OP_TOKEN) headers['X-Op-Token'] = OP_TOKEN;
        const res = await fetch(`${API_BASE}/op/health`, { headers });
        if (res.ok) {
          const data = await res.json();
          setHealth({ ok: true, sessions: data.sessions ?? 0 });
        } else {
          setHealth(null);
        }
      } catch {
        setHealth(null);
      } finally {
        setLoading(false);
      }
    };
    fetchHealth();
    const t = setInterval(fetchHealth, 10000);
    return () => clearInterval(t);
  }, []);

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Dashboard
      </Typography>
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Server Status
              </Typography>
              {!API_BASE && (
                <Typography color="textSecondary">
                  Set REACT_APP_API_URL (e.g. https://localhost:8443) to connect.
                </Typography>
              )}
              {API_BASE && loading && (
                <Box display="flex" alignItems="center" gap={1}>
                  <CircularProgress size={20} />
                  <Typography color="textSecondary">Checking...</Typography>
                </Box>
              )}
              {API_BASE && !loading && (
                <>
                  <Typography color={health?.ok ? 'success.main' : 'error'}>
                    {health?.ok ? 'Reachable' : 'Connection failed'}
                  </Typography>
                  {!health?.ok && (
                    <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
                      Start the C2 server (e.g. <code>./server</code> or Docker) and ensure it listens on the API URL. If using Cursor&apos;s built-in browser, try opening the app in your system browser at http://localhost:3000.
                    </Typography>
                  )}
                </>
              )}
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Active Sessions
              </Typography>
              {!API_BASE && (
                <Typography color="textSecondary">—</Typography>
              )}
              {API_BASE && !loading && (
                <Typography>
                  {health?.ok ? health.sessions : '—'}
                </Typography>
              )}
              {API_BASE && loading && <Typography color="textSecondary">—</Typography>}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Dashboard;
