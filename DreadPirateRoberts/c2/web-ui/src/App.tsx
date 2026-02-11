import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { ThemeProvider, createTheme, CssBaseline } from '@mui/material';
import Layout from './components/Layout';
import Dashboard from './components/Dashboard';
import Clients from './components/Clients';
import SessionHistory from './components/SessionHistory';
import Console from './components/Console';
import FileManager from './components/FileManager';
import Screenshot from './components/Screenshot';
import ProcessList from './components/ProcessList';
import Keylog from './components/Keylog';
import { Audit } from './components';
import C2Log from './components/C2Log';
import Settings from './components/Settings';
import { WaveBackground } from './components/WaveBackground';

const gold = '#c9a227';
const navy = '#0a0e17';
const navyLight = '#12182a';

const nauticalTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: { main: gold },
    secondary: { main: '#8b7355' },
    background: {
      default: navy,
      paper: navyLight,
    },
  },
  typography: {
    fontFamily: '"Segoe UI", Roboto, sans-serif',
    h1: { fontFamily: '"Cinzel", serif' },
    h2: { fontFamily: '"Cinzel", serif' },
    h3: { fontFamily: '"Cinzel", serif' },
    h4: { fontFamily: '"Cinzel", serif' },
    h5: { fontFamily: '"Cinzel", serif' },
    h6: { fontFamily: '"Cinzel", serif' },
  },
  components: {
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          backgroundColor: 'rgba(18, 24, 42, 0.85)',
          border: '1px solid rgba(201, 162, 39, 0.2)',
        },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
          backgroundColor: 'rgba(10, 14, 23, 0.95)',
          borderBottom: `1px solid rgba(201, 162, 39, 0.3)`,
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          backgroundColor: navy,
          borderRight: `1px solid rgba(201, 162, 39, 0.25)`,
        },
      },
    },
  },
});

const App: React.FC = () => {
  return (
    <ThemeProvider theme={nauticalTheme}>
      <CssBaseline />
      <WaveBackground />
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="clients" element={<Clients />} />
            <Route path="history" element={<SessionHistory />} />
            <Route path="console" element={<Console />} />
            <Route path="screenshot" element={<Screenshot />} />
            <Route path="processes" element={<ProcessList />} />
            <Route path="keylog" element={<Keylog />} />
            <Route path="audit" element={<Audit />} />
            <Route path="c2log" element={<C2Log />} />
            <Route path="files" element={<FileManager />} />
            <Route path="settings" element={<Settings />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ThemeProvider>
  );
};

export default App;
