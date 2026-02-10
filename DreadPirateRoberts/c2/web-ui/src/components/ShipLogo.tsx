import React from 'react';
import { Box } from '@mui/material';

const shipLogoUrl = `${process.env.PUBLIC_URL || ''}/ship-logo.svg`;

interface ShipLogoProps {
  size?: number;
}

/**
 * Pirate ship logo – uses asset at public/ship-logo.svg.
 * Source: Wikimedia Commons, Pirate-ship.svg (CC0 / Public Domain).
 */
export const ShipLogo: React.FC<ShipLogoProps> = ({ size = 48 }) => (
  <Box
    component="img"
    src={shipLogoUrl}
    alt=""
    role="presentation"
    sx={{
      display: 'block',
      flexShrink: 0,
      height: size,
      width: 'auto',
      objectFit: 'contain',
      filter: 'brightness(1.1) contrast(1.05)',
      // Optional: tint toward gold to match theme (subtle)
      // filter: 'brightness(1.1) sepia(0.3) saturate(1.2) hue-rotate(5deg)',
    }}
  />
);
