import React from 'react';
import { Box } from '@mui/material';

const NAVY = '#0a0e17';
const NAVY_DARK = '#050810';

export const WaveBackground: React.FC = () => (
  <Box
    sx={{
      position: 'fixed',
      inset: 0,
      zIndex: -1,
      background: `linear-gradient(180deg, ${NAVY} 0%, ${NAVY_DARK} 50%, ${NAVY} 100%)`,
      overflow: 'hidden',
    }}
  >
    {/* Subtle ship silhouette - very low opacity */}
    <Box
      component="svg"
      viewBox="0 0 400 120"
      preserveAspectRatio="xMidYMax slice"
      sx={{
        position: 'absolute',
        bottom: 0,
        left: 0,
        width: '100%',
        height: '35%',
        opacity: 0.06,
        pointerEvents: 'none',
      }}
    >
      <path
        fill="#1a1a2e"
        d="M0 100 L40 80 L80 85 L120 75 L160 80 L200 70 L240 78 L280 72 L320 80 L360 75 L400 85 L400 120 L0 120 Z"
      />
      <path
        fill="none"
        stroke="#2a2a4e"
        strokeWidth="2"
        d="M200 70 L200 30 M190 35 L210 35 M185 45 L215 45"
      />
    </Box>
    {/* Animated waves */}
    <Box
      component="svg"
      viewBox="0 0 1200 120"
      preserveAspectRatio="none"
      sx={{
        position: 'absolute',
        bottom: 0,
        left: 0,
        width: '200%',
        height: '120px',
        opacity: 0.12,
        animation: 'wave-slide 18s linear infinite',
      }}
    >
      <path
        fill="none"
        stroke="#c9a227"
        strokeWidth="0.5"
        d="M0 60 Q150 40 300 60 T600 60 T900 60 T1200 60 L1200 120 L0 120 Z"
      />
      <path
        fill="none"
        stroke="#8b7355"
        strokeWidth="0.5"
        d="M0 80 Q150 60 300 80 T600 80 T900 80 T1200 80 L1200 120 L0 120 Z"
      />
    </Box>
    <Box
      component="svg"
      viewBox="0 0 1200 120"
      preserveAspectRatio="none"
      sx={{
        position: 'absolute',
        bottom: 0,
        left: 0,
        width: '200%',
        height: '120px',
        opacity: 0.08,
        animation: 'wave-slide 22s linear infinite',
        animationDelay: '-7s',
      }}
    >
      <path
        fill="none"
        stroke="#c9a227"
        strokeWidth="0.5"
        d="M0 70 Q200 50 400 70 T800 70 T1200 70 L1200 120 L0 120 Z"
      />
    </Box>
  </Box>
);
