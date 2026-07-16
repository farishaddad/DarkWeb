import type { FraudCategory, IntelligenceTier, Severity } from './models'
import type { AlertSummary } from './api'

export interface AlertFilters {
  categories: FraudCategory[]
  severities: Severity[]
  tiers: IntelligenceTier[]
  timeRange: {
    from: string
    to: string
  }
  searchText: string
  sortBy: 'created_at' | 'severity' | 'category'
  sortOrder: 'asc' | 'desc'
  page: number
  pageSize: number
}

export interface PaginatedAlerts {
  alerts: AlertSummary[]
  totalCount: number
  page: number
  pageSize: number
  hasMore: boolean
}
