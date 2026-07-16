import type { Severity } from './models'
import type { AlertSummary } from './api'

export interface DashboardSummary {
  totalAlerts: number
  alertsBySeverity: Record<Severity, number>
  alertsByCategory: Record<string, number>
  alertsByTier: Record<string, number>
  timelineData: TimelinePoint[]
  recentAlerts: AlertSummary[]
  campaignCount: number
  activeSourceCount: number
}

export interface TimelinePoint {
  timestamp: string
  count: number
  severity: Severity
}
