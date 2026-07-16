import type {
  DashboardSummary,
  PaginatedAlerts,
  AlertDetail,
  RelationshipGraph,
  SignalSource,
  AlertFilters,
  ApiResponse,
} from '../types'

export interface DataProvider {
  fetchDashboardSummary(): Promise<ApiResponse<DashboardSummary>>
  fetchAlerts(filters: AlertFilters): Promise<ApiResponse<PaginatedAlerts>>
  fetchAlertDetail(alertId: string): Promise<ApiResponse<AlertDetail>>
  fetchRelationships(alertId: string): Promise<ApiResponse<RelationshipGraph>>
  fetchSignalSources(alertId: string): Promise<ApiResponse<SignalSource[]>>
}
