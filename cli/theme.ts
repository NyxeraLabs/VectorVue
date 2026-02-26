/*
Copyright (c) 2026 NyxeraLabs
Author: José María Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 → Apache-2.0

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Offer as a commercial service
✘ Sell derived competing products
*/

export const cliTheme = {
  colors: {
    bgPrimary: '#0A0F2D',
    bgSecondary: '#121735',
    accent: '#8A2BE2',
    accentHover: '#9D4DFF',
    metallicStart: '#D9E1F2',
    metallicMid: '#FFFFFF',
    metallicEnd: '#C7CEDB',
    success: '#00C896',
    warning: '#FFB020',
    error: '#FF4D4F',
    textPrimary: '#E6E9F2',
    textSecondary: '#AAB2D5'
  },
  attribution: {
    line1: 'VectorVue by Nyxera Labs',
    line2: '© 2026 Nyxera Labs. All rights reserved.'
  }
} as const;

export type CliTheme = typeof cliTheme;
