export type DataMode = 'mock' | 'live'

export const APP_CONFIG = {
  dataMode: (import.meta.env.VITE_DATA_MODE || 'mock') as DataMode,
  apiBaseUrl: import.meta.env.VITE_API_BASE_URL || '',
  apiKey: import.meta.env.VITE_API_KEY || '',
}
