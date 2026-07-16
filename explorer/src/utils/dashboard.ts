import type { AlertDetail, DashboardSummary, TimelinePoint, AlertSummary } from '../types'
import type { Severity } from '../types'

/**
 * Computes an aggregate dashboard summary from an array of alerts.
 *
 * Precondition: alerts is a valid array (may be empty)
 * Postcondition: returns summary with correct counts matching input data
 *   - totalAlerts === alerts.length
 *   - sum of alertsBySeverity values === totalAlerts
 *   - timelineData sorted chronologically
 *   - recentAlerts contains at most 5 items
 */
export function computeDashboardSummary(alerts: AlertDetail[]): DashboardSummary {
  const alertsBySeverity: Record<Severity, number> = {
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  }
  const alertsByCategory: Record<string, number> = {}
  const alertsByTier: Record<string, number> = {}
  const timelineMap = new Map<string, { count: number; severity: Severity }>()

  for (const alert of alerts) {
    alertsBySeverity[alert.severity]++
    alertsByCategory[alert.category] = (alertsByCategory[alert.category] ?? 0) + 1
    alertsByTier[alert.tier] = (alertsByTier[alert.tier] ?? 0) + 1

    const dateKey = alert.createdAt.substring(0, 10) // YYYY-MM-DD
    const existing = timelineMap.get(dateKey)
    if (existing) {
      existing.count++
    } else {
      timelineMap.set(dateKey, { count: 1, severity: alert.severity })
    }
  }

  const timelineData: TimelinePoint[] = Array.from(timelineMap.entries())
    .map(([timestamp, data]) => ({ timestamp, count: data.count, severity: data.severity }))
    .sort((a, b) => a.timestamp.localeCompare(b.timestamp))

  // Recent alerts: last 5 sorted by createdAt descending
  const recentAlerts: AlertSummary[] = [...alerts]
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    .slice(0, 5)
    .map(alert => ({
      alertId: alert.alertId,
      alertType: alert.alertType,
      severity: alert.severity,
      category: alert.category,
      tier: alert.tier,
      ttpDescription: alert.ttpDescription,
      affectedInstitutions: alert.affectedInstitutions,
      createdAt: alert.createdAt,
      tagCount: alert.tags.length,
    }))

  const campaignCount = alerts.filter(a => a.alertType === 'campaign_alert').length

  const activeSourceCount = new Set(
    alerts.map(a => a.provenance.originalSourceUrl)
  ).size

  return {
    totalAlerts: alerts.length,
    alertsBySeverity,
    alertsByCategory,
    alertsByTier,
    timelineData,
    recentAlerts,
    campaignCount,
    activeSourceCount,
  }
}
