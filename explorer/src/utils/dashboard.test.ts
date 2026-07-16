import { describe, it, expect } from 'vitest'
import { computeDashboardSummary } from './dashboard'
import type { AlertDetail } from '../types'

function makeAlert(overrides: Partial<AlertDetail> = {}): AlertDetail {
  return {
    alertId: 'alert-001',
    alertType: 'ttp_alert',
    severity: 'high',
    category: 'account_takeover',
    tier: 'indicator',
    ttpDescription: 'Test TTP description',
    affectedInstitutions: ['HSBC'],
    detectionRules: [],
    relatedIntelligence: [],
    provenance: {
      originalSourceUrl: 'http://example.onion',
      crawlTimestamp: '2025-01-15T10:00:00Z',
      s3ArtifactKey: 'crawl-artifacts/2025/01/15/001/',
      processingChain: [],
    },
    tags: [{ namespace: 'mitre-attack', predicate: 'technique', value: 'T1531' }],
    galaxyMatch: null,
    createdAt: '2025-01-15T12:00:00Z',
    ...overrides,
  }
}

describe('computeDashboardSummary', () => {
  it('returns zero counts for an empty alert array', () => {
    const result = computeDashboardSummary([])

    expect(result.totalAlerts).toBe(0)
    expect(result.alertsBySeverity).toEqual({ low: 0, medium: 0, high: 0, critical: 0 })
    expect(result.alertsByCategory).toEqual({})
    expect(result.alertsByTier).toEqual({})
    expect(result.timelineData).toEqual([])
    expect(result.recentAlerts).toEqual([])
    expect(result.campaignCount).toBe(0)
    expect(result.activeSourceCount).toBe(0)
  })

  it('computes correct summary for a single alert', () => {
    const alert = makeAlert({
      alertId: 'alert-single',
      severity: 'critical',
      category: 'phishing_kit',
      tier: 'ttp',
      alertType: 'campaign_alert',
      createdAt: '2025-03-10T08:30:00Z',
      provenance: {
        originalSourceUrl: 'http://darkforum.onion',
        crawlTimestamp: '2025-03-10T07:00:00Z',
        s3ArtifactKey: 'crawl-artifacts/2025/03/10/single/',
        processingChain: [],
      },
    })

    const result = computeDashboardSummary([alert])

    expect(result.totalAlerts).toBe(1)
    expect(result.alertsBySeverity).toEqual({ low: 0, medium: 0, high: 0, critical: 1 })
    expect(result.alertsByCategory).toEqual({ phishing_kit: 1 })
    expect(result.alertsByTier).toEqual({ ttp: 1 })
    expect(result.timelineData).toEqual([
      { timestamp: '2025-03-10', count: 1, severity: 'critical' },
    ])
    expect(result.recentAlerts).toHaveLength(1)
    expect(result.recentAlerts[0].alertId).toBe('alert-single')
    expect(result.campaignCount).toBe(1)
    expect(result.activeSourceCount).toBe(1)
  })

  it('computes correct summary for multiple alerts', () => {
    const alerts: AlertDetail[] = [
      makeAlert({
        alertId: 'a1',
        severity: 'low',
        category: 'money_mule',
        tier: 'observable',
        alertType: 'ttp_alert',
        createdAt: '2025-02-01T10:00:00Z',
        provenance: {
          originalSourceUrl: 'http://source-a.onion',
          crawlTimestamp: '2025-02-01T09:00:00Z',
          s3ArtifactKey: 'key-a',
          processingChain: [],
        },
      }),
      makeAlert({
        alertId: 'a2',
        severity: 'high',
        category: 'account_takeover',
        tier: 'indicator',
        alertType: 'campaign_alert',
        createdAt: '2025-02-01T14:00:00Z',
        provenance: {
          originalSourceUrl: 'http://source-b.onion',
          crawlTimestamp: '2025-02-01T13:00:00Z',
          s3ArtifactKey: 'key-b',
          processingChain: [],
        },
      }),
      makeAlert({
        alertId: 'a3',
        severity: 'high',
        category: 'money_mule',
        tier: 'ttp',
        alertType: 'campaign_alert',
        createdAt: '2025-02-03T09:00:00Z',
        provenance: {
          originalSourceUrl: 'http://source-a.onion', // duplicate source
          crawlTimestamp: '2025-02-03T08:00:00Z',
          s3ArtifactKey: 'key-c',
          processingChain: [],
        },
      }),
      makeAlert({
        alertId: 'a4',
        severity: 'medium',
        category: 'phishing_kit',
        tier: 'observable',
        alertType: 'summary_digest',
        createdAt: '2025-02-02T11:00:00Z',
        provenance: {
          originalSourceUrl: 'http://source-c.onion',
          crawlTimestamp: '2025-02-02T10:00:00Z',
          s3ArtifactKey: 'key-d',
          processingChain: [],
        },
      }),
      makeAlert({
        alertId: 'a5',
        severity: 'critical',
        category: 'synthetic_identity',
        tier: 'indicator',
        alertType: 'ttp_alert',
        createdAt: '2025-02-04T16:00:00Z',
        provenance: {
          originalSourceUrl: 'http://source-d.onion',
          crawlTimestamp: '2025-02-04T15:00:00Z',
          s3ArtifactKey: 'key-e',
          processingChain: [],
        },
      }),
      makeAlert({
        alertId: 'a6',
        severity: 'low',
        category: 'cnp_fraud',
        tier: 'observable',
        alertType: 'ttp_alert',
        createdAt: '2025-02-05T08:00:00Z',
        provenance: {
          originalSourceUrl: 'http://source-b.onion', // duplicate source
          crawlTimestamp: '2025-02-05T07:00:00Z',
          s3ArtifactKey: 'key-f',
          processingChain: [],
        },
      }),
    ]

    const result = computeDashboardSummary(alerts)

    // totalAlerts
    expect(result.totalAlerts).toBe(6)

    // severity distribution sums to total
    const severitySum =
      result.alertsBySeverity.low +
      result.alertsBySeverity.medium +
      result.alertsBySeverity.high +
      result.alertsBySeverity.critical
    expect(severitySum).toBe(6)
    expect(result.alertsBySeverity).toEqual({ low: 2, medium: 1, high: 2, critical: 1 })

    // category breakdown
    expect(result.alertsByCategory).toEqual({
      money_mule: 2,
      account_takeover: 1,
      phishing_kit: 1,
      synthetic_identity: 1,
      cnp_fraud: 1,
    })

    // tier breakdown
    expect(result.alertsByTier).toEqual({ observable: 3, indicator: 2, ttp: 1 })

    // timeline sorted chronologically
    expect(result.timelineData).toHaveLength(5)
    expect(result.timelineData[0].timestamp).toBe('2025-02-01')
    expect(result.timelineData[0].count).toBe(2) // two alerts on Feb 1
    expect(result.timelineData[1].timestamp).toBe('2025-02-02')
    expect(result.timelineData[2].timestamp).toBe('2025-02-03')
    expect(result.timelineData[3].timestamp).toBe('2025-02-04')
    expect(result.timelineData[4].timestamp).toBe('2025-02-05')

    // recentAlerts: last 5 by createdAt descending
    expect(result.recentAlerts).toHaveLength(5)
    expect(result.recentAlerts[0].alertId).toBe('a6') // Feb 5
    expect(result.recentAlerts[1].alertId).toBe('a5') // Feb 4
    expect(result.recentAlerts[2].alertId).toBe('a3') // Feb 3
    expect(result.recentAlerts[3].alertId).toBe('a4') // Feb 2
    expect(result.recentAlerts[4].alertId).toBe('a2') // Feb 1 14:00

    // campaignCount: only 'campaign_alert' types
    expect(result.campaignCount).toBe(2) // a2 and a3

    // activeSourceCount: distinct source URLs
    expect(result.activeSourceCount).toBe(4) // source-a, source-b, source-c, source-d
  })

  it('limits recentAlerts to 5 even with more alerts', () => {
    const alerts = Array.from({ length: 10 }, (_, i) =>
      makeAlert({
        alertId: `alert-${i}`,
        createdAt: `2025-01-${String(i + 1).padStart(2, '0')}T10:00:00Z`,
      })
    )

    const result = computeDashboardSummary(alerts)

    expect(result.recentAlerts).toHaveLength(5)
    // Most recent first
    expect(result.recentAlerts[0].alertId).toBe('alert-9')
    expect(result.recentAlerts[4].alertId).toBe('alert-5')
  })

  it('counts only campaign_alert for campaignCount and excludes other types', () => {
    const alerts = [
      makeAlert({ alertId: 'c1', alertType: 'campaign_alert' }),
      makeAlert({ alertId: 'c2', alertType: 'ttp_alert' }),
      makeAlert({ alertId: 'c3', alertType: 'summary_digest' }),
      makeAlert({ alertId: 'c4', alertType: 'campaign_alert' }),
    ]

    const result = computeDashboardSummary(alerts)

    expect(result.campaignCount).toBe(2)
  })

  it('counts distinct source URLs for activeSourceCount', () => {
    const alerts = [
      makeAlert({
        alertId: 'd1',
        provenance: {
          originalSourceUrl: 'http://same.onion',
          crawlTimestamp: '2025-01-01T00:00:00Z',
          s3ArtifactKey: 'k1',
          processingChain: [],
        },
      }),
      makeAlert({
        alertId: 'd2',
        provenance: {
          originalSourceUrl: 'http://same.onion',
          crawlTimestamp: '2025-01-02T00:00:00Z',
          s3ArtifactKey: 'k2',
          processingChain: [],
        },
      }),
      makeAlert({
        alertId: 'd3',
        provenance: {
          originalSourceUrl: 'http://different.onion',
          crawlTimestamp: '2025-01-03T00:00:00Z',
          s3ArtifactKey: 'k3',
          processingChain: [],
        },
      }),
    ]

    const result = computeDashboardSummary(alerts)

    expect(result.activeSourceCount).toBe(2)
  })
})
