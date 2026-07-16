import { describe, it, expect } from 'vitest'
import { applyFilters } from './filters'
import type { AlertSummary } from '../types/api'
import type { AlertFilters } from '../types/filters'

function makeAlert(overrides: Partial<AlertSummary> = {}): AlertSummary {
  return {
    alertId: 'alert-001',
    alertType: 'ttp_alert',
    severity: 'medium',
    category: 'account_takeover',
    tier: 'indicator',
    ttpDescription: 'Credential stuffing attack detected',
    affectedInstitutions: ['HSBC', 'Barclays'],
    createdAt: '2025-03-15T10:00:00Z',
    tagCount: 5,
    ...overrides,
  }
}

function makeFilters(overrides: Partial<AlertFilters> = {}): AlertFilters {
  return {
    categories: [],
    severities: [],
    tiers: [],
    timeRange: { from: '', to: '' },
    searchText: '',
    sortBy: 'created_at',
    sortOrder: 'asc',
    page: 1,
    pageSize: 20,
    ...overrides,
  }
}

const sampleAlerts: AlertSummary[] = [
  makeAlert({
    alertId: 'alert-001',
    severity: 'critical',
    category: 'mfa_bypass',
    tier: 'ttp',
    ttpDescription: 'MFA bypass using SIM swap',
    affectedInstitutions: ['HSBC'],
    createdAt: '2025-03-10T08:00:00Z',
  }),
  makeAlert({
    alertId: 'alert-002',
    severity: 'high',
    category: 'account_takeover',
    tier: 'indicator',
    ttpDescription: 'Credential stuffing campaign targeting banks',
    affectedInstitutions: ['Barclays', 'NatWest'],
    createdAt: '2025-03-12T14:30:00Z',
  }),
  makeAlert({
    alertId: 'alert-003',
    severity: 'medium',
    category: 'phishing_kit',
    tier: 'observable',
    ttpDescription: 'Phishing kit deployment on dark web forum',
    affectedInstitutions: ['Lloyds'],
    createdAt: '2025-03-14T09:15:00Z',
  }),
  makeAlert({
    alertId: 'alert-004',
    severity: 'low',
    category: 'money_mule',
    tier: 'observable',
    ttpDescription: 'Money mule recruitment advertisement',
    affectedInstitutions: ['Santander', 'HSBC'],
    createdAt: '2025-03-16T16:45:00Z',
  }),
  makeAlert({
    alertId: 'alert-005',
    severity: 'high',
    category: 'synthetic_identity',
    tier: 'ttp',
    ttpDescription: 'Synthetic identity fraud ring detected',
    affectedInstitutions: ['Metro Bank'],
    createdAt: '2025-03-18T11:00:00Z',
  }),
]

describe('applyFilters', () => {
  describe('empty filters', () => {
    it('returns all alerts when no filters are active', () => {
      const result = applyFilters(sampleAlerts, makeFilters())
      expect(result).toHaveLength(sampleAlerts.length)
    })
  })

  describe('category filter', () => {
    it('filters by single category', () => {
      const result = applyFilters(
        sampleAlerts,
        makeFilters({ categories: ['mfa_bypass'] })
      )
      expect(result).toHaveLength(1)
      expect(result[0].alertId).toBe('alert-001')
    })

    it('filters by multiple categories', () => {
      const result = applyFilters(
        sampleAlerts,
        makeFilters({ categories: ['mfa_bypass', 'account_takeover'] })
      )
      expect(result).toHaveLength(2)
      expect(result.every((a) => ['mfa_bypass', 'account_takeover'].includes(a.category))).toBe(true)
    })

    it('returns empty when no alerts match category', () => {
      const result = applyFilters(
        sampleAlerts,
        makeFilters({ categories: ['investment_fraud'] })
      )
      expect(result).toHaveLength(0)
    })
  })

  describe('severity filter', () => {
    it('filters by single severity', () => {
      const result = applyFilters(
        sampleAlerts,
        makeFilters({ severities: ['critical'] })
      )
      expect(result).toHaveLength(1)
      expect(result[0].severity).toBe('critical')
    })

    it('filters by multiple severities', () => {
      const result = applyFilters(
        sampleAlerts,
        makeFilters({ severities: ['high', 'critical'] })
      )
      expect(result).toHaveLength(3)
      expect(result.every((a) => ['high', 'critical'].includes(a.severity))).toBe(true)
    })
  })

  describe('tier filter', () => {
    it('filters by single tier', () => {
      const result = applyFilters(
        sampleAlerts,
        makeFilters({ tiers: ['ttp'] })
      )
      expect(result).toHaveLength(2)
      expect(result.every((a) => a.tier === 'ttp')).toBe(true)
    })

    it('filters by multiple tiers', () => {
      const result = applyFilters(
        sampleAlerts,
        makeFilters({ tiers: ['observable', 'indicator'] })
      )
      expect(result).toHaveLength(3)
    })
  })

  describe('time range filter', () => {
    it('filters by from date (inclusive)', () => {
      const result = applyFilters(
        sampleAlerts,
        makeFilters({ timeRange: { from: '2025-03-14T00:00:00Z', to: '' } })
      )
      expect(result).toHaveLength(3)
      expect(result.every((a) => a.createdAt >= '2025-03-14T00:00:00Z')).toBe(true)
    })

    it('filters by to date (inclusive)', () => {
      const result = applyFilters(
        sampleAlerts,
        makeFilters({ timeRange: { from: '', to: '2025-03-14T09:15:00Z' } })
      )
      expect(result).toHaveLength(3)
      expect(result.every((a) => a.createdAt <= '2025-03-14T09:15:00Z')).toBe(true)
    })

    it('filters by both from and to (inclusive)', () => {
      const result = applyFilters(
        sampleAlerts,
        makeFilters({
          timeRange: { from: '2025-03-12T00:00:00Z', to: '2025-03-15T00:00:00Z' },
        })
      )
      expect(result).toHaveLength(2)
      expect(result.map((a) => a.alertId).sort()).toEqual(['alert-002', 'alert-003'])
    })
  })

  describe('search text filter', () => {
    it('matches TTP description case-insensitively', () => {
      const result = applyFilters(
        sampleAlerts,
        makeFilters({ searchText: 'sim swap' })
      )
      expect(result).toHaveLength(1)
      expect(result[0].alertId).toBe('alert-001')
    })

    it('matches affected institution case-insensitively', () => {
      const result = applyFilters(
        sampleAlerts,
        makeFilters({ searchText: 'hsbc' })
      )
      expect(result).toHaveLength(2)
      expect(result.map((a) => a.alertId).sort()).toEqual(['alert-001', 'alert-004'])
    })

    it('matches substring in TTP description', () => {
      const result = applyFilters(
        sampleAlerts,
        makeFilters({ searchText: 'phishing' })
      )
      expect(result).toHaveLength(1)
      expect(result[0].alertId).toBe('alert-003')
    })

    it('returns empty for non-matching text', () => {
      const result = applyFilters(
        sampleAlerts,
        makeFilters({ searchText: 'nonexistent_xyz' })
      )
      expect(result).toHaveLength(0)
    })
  })

  describe('combined filters (AND logic)', () => {
    it('applies category AND severity together', () => {
      const result = applyFilters(
        sampleAlerts,
        makeFilters({
          categories: ['mfa_bypass', 'account_takeover', 'synthetic_identity'],
          severities: ['high'],
        })
      )
      expect(result).toHaveLength(2)
      expect(result.every((a) => a.severity === 'high')).toBe(true)
      expect(
        result.every((a) =>
          ['mfa_bypass', 'account_takeover', 'synthetic_identity'].includes(a.category)
        )
      ).toBe(true)
    })

    it('applies time range AND search text together', () => {
      const result = applyFilters(
        sampleAlerts,
        makeFilters({
          timeRange: { from: '2025-03-11T00:00:00Z', to: '2025-03-17T00:00:00Z' },
          searchText: 'bank',
        })
      )
      // alert-002 matches: timeRange and 'banks' in description
      expect(result).toHaveLength(1)
      expect(result[0].alertId).toBe('alert-002')
    })
  })

  describe('sorting', () => {
    it('sorts by created_at ascending', () => {
      const result = applyFilters(
        sampleAlerts,
        makeFilters({ sortBy: 'created_at', sortOrder: 'asc' })
      )
      for (let i = 1; i < result.length; i++) {
        expect(result[i].createdAt >= result[i - 1].createdAt).toBe(true)
      }
    })

    it('sorts by created_at descending', () => {
      const result = applyFilters(
        sampleAlerts,
        makeFilters({ sortBy: 'created_at', sortOrder: 'desc' })
      )
      for (let i = 1; i < result.length; i++) {
        expect(result[i].createdAt <= result[i - 1].createdAt).toBe(true)
      }
    })

    it('sorts by severity ascending (low < medium < high < critical)', () => {
      const result = applyFilters(
        sampleAlerts,
        makeFilters({ sortBy: 'severity', sortOrder: 'asc' })
      )
      const severityOrder = { low: 0, medium: 1, high: 2, critical: 3 }
      for (let i = 1; i < result.length; i++) {
        expect(severityOrder[result[i].severity] >= severityOrder[result[i - 1].severity]).toBe(true)
      }
    })

    it('sorts by severity descending (critical > high > medium > low)', () => {
      const result = applyFilters(
        sampleAlerts,
        makeFilters({ sortBy: 'severity', sortOrder: 'desc' })
      )
      const severityOrder = { low: 0, medium: 1, high: 2, critical: 3 }
      for (let i = 1; i < result.length; i++) {
        expect(severityOrder[result[i].severity] <= severityOrder[result[i - 1].severity]).toBe(true)
      }
    })

    it('sorts by category ascending (alphabetical)', () => {
      const result = applyFilters(
        sampleAlerts,
        makeFilters({ sortBy: 'category', sortOrder: 'asc' })
      )
      for (let i = 1; i < result.length; i++) {
        expect(result[i].category.localeCompare(result[i - 1].category) >= 0).toBe(true)
      }
    })

    it('sorts by category descending', () => {
      const result = applyFilters(
        sampleAlerts,
        makeFilters({ sortBy: 'category', sortOrder: 'desc' })
      )
      for (let i = 1; i < result.length; i++) {
        expect(result[i].category.localeCompare(result[i - 1].category) <= 0).toBe(true)
      }
    })
  })

  describe('edge cases', () => {
    it('returns empty array for empty input', () => {
      const result = applyFilters([], makeFilters())
      expect(result).toHaveLength(0)
    })

    it('does not mutate original array', () => {
      const original = [...sampleAlerts]
      applyFilters(sampleAlerts, makeFilters({ sortBy: 'severity', sortOrder: 'desc' }))
      expect(sampleAlerts).toEqual(original)
    })

    it('returns filtered+sorted result', () => {
      const result = applyFilters(
        sampleAlerts,
        makeFilters({
          severities: ['high', 'critical'],
          sortBy: 'severity',
          sortOrder: 'desc',
        })
      )
      expect(result).toHaveLength(3)
      expect(result[0].severity).toBe('critical')
      expect(result[1].severity).toBe('high')
      expect(result[2].severity).toBe('high')
    })
  })
})
