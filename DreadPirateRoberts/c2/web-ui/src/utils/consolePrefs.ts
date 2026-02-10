const STORAGE_KEY = 'c2-console-prefs';

export type ConsoleTheme = 'default' | 'green' | 'amber';

export type ConsolePrefs = {
  fontSize: number;
  theme: ConsoleTheme;
};

const DEFAULTS: ConsolePrefs = {
  fontSize: 14,
  theme: 'default',
};

export function getConsolePrefs(): ConsolePrefs {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULTS;
    const parsed = JSON.parse(raw) as Partial<ConsolePrefs>;
    return {
      fontSize: typeof parsed.fontSize === 'number' && parsed.fontSize >= 10 && parsed.fontSize <= 24
        ? parsed.fontSize
        : DEFAULTS.fontSize,
      theme: ['default', 'green', 'amber'].includes(parsed.theme ?? '') ? (parsed.theme as ConsoleTheme) : DEFAULTS.theme,
    };
  } catch {
    return DEFAULTS;
  }
}

export function setConsolePrefs(prefs: Partial<ConsolePrefs>): void {
  const next = { ...getConsolePrefs(), ...prefs };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
  window.dispatchEvent(new CustomEvent('console-prefs-changed'));
}

export function getTerminalStyles(prefs: ConsolePrefs): { bgcolor: string; color: string } {
  switch (prefs.theme) {
    case 'green':
      return { bgcolor: '#0a0f0a', color: '#33ff33' };
    case 'amber':
      return { bgcolor: '#1a1510', color: '#ffb347' };
    default:
      return { bgcolor: '#1e1e1e', color: '#fff' };
  }
}
