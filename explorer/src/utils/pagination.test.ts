import { describe, it, expect } from 'vitest'
import { paginate } from './pagination'
import type { AlertSummary } from '../types/api'

function createMockAlert(index: number): AlertSummary {
  return {
    alertId: `alert-${index}`,
    alertType: 'ttp_alert',
    severity: 'high',
    category: 'account_takeover',
    tier: 'indicator',
    ttpDescription: `Alert ${index} description`,
    affectedInstitutions: ['TestBank'],
    createdAt: '2025-01-15T10:00:00Z',
    tagCount: 3,
  }
}

function createAlerts(count: number): AlertSummary[] {
  return Array.from({ length: count }, (_, i) => createMockAlert(i))
}

describe('paginate', () => {
  describe('validation', () => {
    it('throws when page is less than 1', () => {
      const alerts = createAlerts(20)
      expect(() => paginate(alerts, 0, 10)).toThrow(
        'Invalid page: 0. Page must be greater than or equal to 1.'
      )
    })

    it('throws when page is negative', () => {
      const alerts = createAlerts(20)
      expect(() => paginate(alerts, -1, 10)).toThrow(
        'Invalid page: -1. Page must be greater than or equal to 1.'
      )
    })

    it('throws when pageSize is less than 10', () => {
      const alerts = createAlerts(20)
      expect(() => paginate(alerts, 1, 9)).toThrow(
        'Invalid pageSize: 9. Page size must be between 10 and 100.'
      )
    })

    it('throws when pageSize is greater than 100', () => {
      const alerts = createAlerts(200)
      expect(() => paginate(alerts, 1, 101)).toThrow(
        'Invalid pageSize: 101. Page size must be between 10 and 100.'
      )
    })
  })

  describe('pagination logic', () => {
    it('returns the first page correctly', () => {
      const alerts = createAlerts(25)
      const result = paginate(alerts, 1, 10)

      expect(result.alerts).toHaveLength(10)
      expect(result.totalCount).toBe(25)
      expect(result.page).toBe(1)
      expect(result.pageSize).toBe(10)
      expect(result.hasMore).toBe(true)
      expect(result.alerts[0].alertId).toBe('alert-0')
      expect(result.alerts[9].alertId).toBe('alert-9')
    })

    it('returns the second page correctly', () => {
      const alerts = createAlerts(25)
      const result = paginate(alerts, 2, 10)

      expect(result.alerts).toHaveLength(10)
      expect(result.totalCount).toBe(25)
      expect(result.page).toBe(2)
      expect(result.hasMore).toBe(true)
      expect(result.alerts[0].alertId).toBe('alert-10')
      expect(result.alerts[9].alertId).toBe('alert-19')
    })

    it('returns a partial last page correctly', () => {
      const alerts = createAlerts(25)
      const result = paginate(alerts, 3, 10)

      expect(result.alerts).toHaveLength(5)
      expect(result.totalCount).toBe(25)
      expect(result.page).toBe(3)
      expect(result.hasMore).toBe(false)
    })

    it('returns empty alerts for page beyond data', () => {
      const alerts = createAlerts(10)
      const result = paginate(alerts, 2, 10)

      expect(result.alerts).toHaveLength(0)
      expect(result.totalCount).toBe(10)
      expect(result.page).toBe(2)
      expect(result.hasMore).toBe(false)
    })

    it('handles empty alerts array', () => {
      const result = paginate([], 1, 10)

      expect(result.alerts).toHaveLength(0)
      expect(result.totalCount).toBe(0)
      expect(result.page).toBe(1)
      expect(result.hasMore).toBe(false)
    })

    it('works with minimum pageSize of 10', () => {
      const alerts = createAlerts(15)
      const result = paginate(alerts, 1, 10)

      expect(result.alerts).toHaveLength(10)
      expect(result.hasMore).toBe(true)
    })

    it('works with maximum pageSize of 100', () => {
      const alerts = createAlerts(150)
      const result = paginate(alerts, 1, 100)

      expect(result.alerts).toHaveLength(100)
      expect(result.hasMore).toBe(true)
    })

    it('returns hasMore false when exactly filling a page', () => {
      const alerts = createAlerts(20)
      const result = paginate(alerts, 2, 10)

      expect(result.alerts).toHaveLength(10)
      expect(result.hasMore).toBe(false)
    })

    it('ensures no alert appears on more than one page (disjointness)', () => {
      const alerts = createAlerts(35)
      const page1 = paginate(alerts, 1, 10)
      const page2 = paginate(alerts, 2, 10)
      const page3 = paginate(alerts, 3, 10)
      const page4 = paginate(alerts, 4, 10)

      const allIds = [
        ...page1.alerts.map(a => a.alertId),
        ...page2.alerts.map(a => a.alertId),
        ...page3.alerts.map(a => a.alertId),
        ...page4.alerts.map(a => a.alertId),
      ]

      const uniqueIds = new Set(allIds)
      expect(uniqueIds.size).toBe(allIds.length)
    })

    it('ensures all alerts are covered across all pages (completeness)', () => {
      const alerts = createAlerts(35)
      const page1 = paginate(alerts, 1, 10)
      const page2 = paginate(alerts, 2, 10)
      const page3 = paginate(alerts, 3, 10)
      const page4 = paginate(alerts, 4, 10)

      const allAlerts = [
        ...page1.alerts,
        ...page2.alerts,
        ...page3.alerts,
        ...page4.alerts,
      ]

      expect(allAlerts).toHaveLength(35)
    })
  })
})
