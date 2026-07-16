import type { SourceType } from './models'

export interface SignalSource {
  sourceId: string
  sourceType: SourceType
  sourceUrl: string
  crawlTimestamp: string
  contentSnippet: string
  confidence: number
  entities: ExtractedEntity[]
  guardRailResult: 'PASSED' | 'FILTERED' | 'FLAGGED'
}

export interface ExtractedEntity {
  entityType: string
  value: string
  context: string
  confidence: number
}
