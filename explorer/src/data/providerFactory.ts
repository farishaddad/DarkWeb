import type { DataProvider } from './provider'

export type DataMode = 'mock' | 'live'

export interface ProviderConfig {
  mode: DataMode
  baseUrl?: string
  apiKey?: string
}

export function createDataProvider(config: ProviderConfig): DataProvider {
  if (config.mode === 'live') {
    // Lazy import to avoid bundling live provider in mock-only builds
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { LiveProvider } = require('./liveProvider')
    return new LiveProvider(config.baseUrl!, config.apiKey) as DataProvider
  }
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { MockProvider } = require('./mockProvider')
  return new MockProvider() as DataProvider
}
