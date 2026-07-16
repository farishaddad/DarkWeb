import type { DataProvider } from './provider'
import type {
  ApiResponse,
  DashboardSummary,
  PaginatedAlerts,
  AlertDetail,
  AlertFilters,
  RelationshipGraph,
  SignalSource,
} from '../types'
import { ApiError } from './errors'

const DEFAULT_TIMEOUT = 30000
const MAX_RETRIES = 4
const INITIAL_BACKOFF = 1000

export class LiveProvider implements DataProvider {
  constructor(
    private baseUrl: string,
    private apiKey?: string
  ) {}

  private async fetchWithRetry<T>(path: string): Promise<ApiResponse<T>> {
    let lastError: Error | null = null

    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      try {
        const controller = new AbortController()
        const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT)

        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
        }
        if (this.apiKey) {
          headers['x-api-key'] = this.apiKey
        }

        const response = await fetch(`${this.baseUrl}${path}`, {
          headers,
          signal: controller.signal,
        })
        clearTimeout(timeout)

        if (response.ok) {
          return (await response.json()) as ApiResponse<T>
        }

        if (response.status >= 500) {
          lastError = new ApiError(
            'SERVER_ERROR',
            `Server error: ${response.status}`,
            response.status
          )
          await this.backoff(attempt)
          continue
        }

        throw new ApiError(
          'CLIENT_ERROR',
          `Request failed: ${response.status}`,
          response.status
        )
      } catch (e) {
        if (e instanceof ApiError && e.code === 'CLIENT_ERROR') {
          throw e
        }
        lastError = e as Error
        await this.backoff(attempt)
      }
    }

    throw lastError || new ApiError('UNKNOWN', 'Request failed after retries')
  }

  private backoff(attempt: number): Promise<void> {
    const delay = Math.min(INITIAL_BACKOFF * Math.pow(2, attempt), 30000)
    return new Promise((resolve) => setTimeout(resolve, delay))
  }

  async fetchDashboardSummary(): Promise<ApiResponse<DashboardSummary>> {
    return this.fetchWithRetry<DashboardSummary>('/api/dashboard/summary')
  }

  async fetchAlerts(filters: AlertFilters): Promise<ApiResponse<PaginatedAlerts>> {
    const params = new URLSearchParams({
      page: String(filters.page),
      pageSize: String(filters.pageSize),
    })

    if (filters.categories.length) {
      params.set('categories', filters.categories.join(','))
    }
    if (filters.severities.length) {
      params.set('severities', filters.severities.join(','))
    }
    if (filters.tiers.length) {
      params.set('tiers', filters.tiers.join(','))
    }
    if (filters.timeRange.from) {
      params.set('from', filters.timeRange.from)
    }
    if (filters.timeRange.to) {
      params.set('to', filters.timeRange.to)
    }
    if (filters.searchText) {
      params.set('search', filters.searchText)
    }
    if (filters.sortBy) {
      params.set('sortBy', filters.sortBy)
    }
    if (filters.sortOrder) {
      params.set('sortOrder', filters.sortOrder)
    }

    return this.fetchWithRetry<PaginatedAlerts>(`/api/alerts?${params}`)
  }

  async fetchAlertDetail(alertId: string): Promise<ApiResponse<AlertDetail>> {
    return this.fetchWithRetry<AlertDetail>(`/api/alerts/${alertId}`)
  }

  async fetchRelationships(alertId: string): Promise<ApiResponse<RelationshipGraph>> {
    return this.fetchWithRetry<RelationshipGraph>(
      `/api/alerts/${alertId}/relationships`
    )
  }

  async fetchSignalSources(alertId: string): Promise<ApiResponse<SignalSource[]>> {
    return this.fetchWithRetry<SignalSource[]>(
      `/api/alerts/${alertId}/sources`
    )
  }
}
