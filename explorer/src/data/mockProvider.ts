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
import { computeDashboardSummary } from '../utils/dashboard'
import { applyFilters } from '../utils/filters'
import { paginate } from '../utils/pagination'
import { buildRelationshipGraph } from '../utils/graph'
import mockData from './mockDataset.json'

export class MockProvider implements DataProvider {
  private alerts: AlertDetail[] = mockData.alerts as unknown as AlertDetail[]
  private signalSources: Record<string, SignalSource[]> =
    mockData.signalSources as unknown as Record<string, SignalSource[]>

  private wrap<T>(data: T): ApiResponse<T> {
    return {
      data,
      meta: {
        requestId: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        dataSource: 'mock',
      },
    }
  }

  async fetchDashboardSummary(): Promise<ApiResponse<DashboardSummary>> {
    return this.wrap(computeDashboardSummary(this.alerts))
  }

  async fetchAlerts(filters: AlertFilters): Promise<ApiResponse<PaginatedAlerts>> {
    const summaries = this.alerts.map((a) => ({
      alertId: a.alertId,
      alertType: a.alertType,
      severity: a.severity,
      category: a.category,
      tier: a.tier,
      ttpDescription: a.ttpDescription,
      affectedInstitutions: a.affectedInstitutions,
      createdAt: a.createdAt,
      tagCount: a.tags.length,
    }))
    const filtered = applyFilters(summaries, filters)
    return this.wrap(paginate(filtered, filters.page, filters.pageSize))
  }

  async fetchAlertDetail(alertId: string): Promise<ApiResponse<AlertDetail>> {
    const alert = this.alerts.find((a) => a.alertId === alertId)
    if (!alert) {
      throw new ApiError('NOT_FOUND', `Alert ${alertId} not found`, 404)
    }
    return this.wrap(alert)
  }

  async fetchRelationships(alertId: string): Promise<ApiResponse<RelationshipGraph>> {
    const alert = this.alerts.find((a) => a.alertId === alertId)
    const related = alert
      ? [alert, ...this.alerts.filter((a) => a.alertId !== alertId).slice(0, 5)]
      : []
    return this.wrap(buildRelationshipGraph(related))
  }

  async fetchSignalSources(alertId: string): Promise<ApiResponse<SignalSource[]>> {
    return this.wrap(this.signalSources[alertId] ?? [])
  }
}
