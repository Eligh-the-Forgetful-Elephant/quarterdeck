import React from 'react';
import { Box, Typography } from '@mui/material';

const gold = '#c9a227';

const shipImageUrl = `${process.env.PUBLIC_URL || ''}/pirate-ship.png`;

interface QuarterdeckLogoProps {
  /** Ship + text block height (ship scales with this). */
  size?: 'small' | 'medium' | 'large';
  /** Show only the ship (no text). */
  shipOnly?: boolean;
  /** Apply glint animation to the wordmark (e.g. for app bar). */
  glint?: boolean;
}

const sizes = {
  small: { ship: 28, fontSize: '1rem' },
  medium: { ship: 40, fontSize: '1.35rem' },
  large: { ship: 56, fontSize: '1.75rem' },
};

/**
 * Quarterdeck branding: custom pirate ship image + wordmark.
 */
export const QuarterdeckLogo: React.FC<QuarterdeckLogoProps> = ({
  size = 'medium',
  shipOnly = false,
  glint = false,
}) => {
  const { ship: shipSize, fontSize } = sizes[size];

  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
      <Box
        component="img"
        src={shipImageUrl}
        alt=""
        role="presentation"
        sx={{
          height: shipSize,
          width: 'auto',
          maxWidth: shipSize * 1.8,
          objectFit: 'contain',
          flexShrink: 0,
        }}
      />
      {!shipOnly && (
        <Typography
          component="span"
          sx={{
            fontFamily: '"Cinzel", serif',
            fontWeight: 700,
            color: gold,
            fontSize,
            letterSpacing: '0.06em',
            textTransform: 'uppercase',
            textShadow: `0 0 20px rgba(201, 162, 39, 0.4)`,
            ...(glint && { animation: 'glint 4s ease-in-out infinite' }),
          }}
        >
          Quarterdeck
        </Typography>
      )}
    </Box>
  );
};
