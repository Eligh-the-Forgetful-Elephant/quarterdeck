import React from 'react';
import {
  Box,
  Paper,
  Typography,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Grid,
} from '@mui/material';
import { Folder as FolderIcon } from '@mui/icons-material';

const FileManager: React.FC = () => {
  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        File Manager
      </Typography>
      <Grid container spacing={2}>
        <Grid item xs={12}>
          <FormControl fullWidth>
            <InputLabel>Target Client</InputLabel>
            <Select label="Target Client" disabled>
              <MenuItem value="">No clients available</MenuItem>
            </Select>
          </FormControl>
        </Grid>
        <Grid item xs={12}>
          <Paper sx={{ p: 2 }}>
            <List>
              <ListItemButton disabled>
                <ListItemIcon>
                  <FolderIcon />
                </ListItemIcon>
                <ListItemText
                  primary="No files available"
                  secondary="Connect to a client to view files"
                />
              </ListItemButton>
            </List>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default FileManager; 