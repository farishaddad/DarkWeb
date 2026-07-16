import { create } from 'zustand'
import type { DataProvider } from '../data/provider'
import type {
  DashboardSummary,
  PaginatedAlerts,
  AlertDetail,
  RelationshipGraph,
  SignalSource,
  AlertFilters,
} from '../types'

interface LoadingState {
  dashboard: boolean
  alerts: boolean
  detail: boolean
  graph: boolean
  sources: boolean
}

interface AppState {
  dataProvider: DataProvider | null
  dashboardSummary: DashboardSummary | null
  alertList: PaginatedAlerts | null
  currentAlert: AlertDetail | null
  relationships: RelationshipGraph | null
  signalSources: SignalSource[]
  filters: AlertFilters
  loading: LoadingState
  error: string | null
  setProvider: (provider: DataProvider) => void
  loadDashboard: () => Promise<void>
  loadAlerts: () => Promise<void>
  loadAlertDetail: (alertId: string) => Promise<void>
  loadRelationships: (alertId: string) => Promise<void>
  loadSignalSources: (alertId: string) => Promise<void>
  setFilters: (filters: Partial<AlertFilters>) => void
  setPage: (page: number) => void
}

const DEFAULT_FILTERS: AlertFilters = {
  categories: [],
  severities: [],
  tiers: [],
  timeRange: { from: '', to: '' },
  searchText: '',
  sortBy: 'created_at',
  sortOrder: 'desc',
  page: 1,
  pageSize: 20,
}

export const useAppStore = create<AppState>((set, get) => ({
  dataProvider: null,
  dashboardSummary: null,
  alertList: null,
  currentAlert: null,
  relationships: null,
  signalSources: [],
  filters: DEFAULT_FILTERS,
  loading: {
    dashboard: false,
    alerts: false,
    detail: false,
    graph: false,
    sources: false,
  },
  error: null,

  setProvider: (provider: DataProvider) => {
    set({ dataProvider: provider })
  },

  loadDashboard: async () => {
    const { dataProvider } = get()
    if (!dataProvider) return

    set({ loading: { ...get().loading, dashboard: true }, error: null })
    try {
      const response = await dataProvider.fetchDashboardSummary()
      set({
        dashboardSummary: response.data,
        loading: { ...get().loading, dashboard: false },
      })
    } catch (err) {
      set({
        error: err instanceof Error ? err.message : 'Failed to load dashboard',
        loading: { ...get().loading, dashboard: false },
      })
    }
  },

  loadAlerts: async () => {
    const { dataProvider, filters } = get()
    if (!dataProvider) return

    set({ loading: { ...get().loading, alerts: true }, error: null })
    try {
      const response = await dataProvider.fetchAlerts(filters)
      set({
        alertList: response.data,
        loading: { ...get().loading, alerts: false },
      })
    } catch (err) {
      set({
        error: err instanceof Error ? err.message : 'Failed to load alerts',
        loading: { ...get().loading, alerts: false },
      })
    }
  },

  loadAlertDetail: async (alertId: string) => {
    const { dataProvider } = get()
    if (!dataProvider) return

    set({ loading: { ...get().loading, detail: true }, error: null })
    try {
      const response = await dataProvider.fetchAlertDetail(alertId)
      set({
        currentAlert: response.data,
        loading: { ...get().loading, detail: false },
      })
    } catch (err) {
      set({
        error: err instanceof Error ? err.message : 'Failed to load alert detail',
        loading: { ...get().loading, detail: false },
      })
    }
  },

  loadRelationships: async (alertId: string) => {
    const { dataProvider } = get()
    if (!dataProvider) return

    set({ loading: { ...get().loading, graph: true }, error: null })
    try {
      const response = await dataProvider.fetchRelationships(alertId)
      set({
        relationships: response.data,
        loading: { ...get().loading, graph: false },
      })
    } catch (err) {
      set({
        error: err instanceof Error ? err.message : 'Failed to load relationships',
        loading: { ...get().loading, graph: false },
      })
    }
  },

  loadSignalSources: async (alertId: string) => {
    const { dataProvider } = get()
    if (!dataProvider) return

    set({ loading: { ...get().loading, sources: true }, error: null })
    try {
      const response = await dataProvider.fetchSignalSources(alertId)
      set({
        signalSources: response.data,
        loading: { ...get().loading, sources: false },
      })
    } catch (err) {
      set({
        error: err instanceof Error ? err.message : 'Failed to load signal sources',
        loading: { ...get().loading, sources: false },
      })
    }
  },

  setFilters: (newFilters: Partial<AlertFilters>) => {
    const { filters } = get()
    set({
      filters: { ...filters, ...newFilters, page: 1 },
    })
  },

  setPage: (page: number) => {
    const { filters } = get()
    set({
      filters: { ...filters, page },
    })
  },
}))
