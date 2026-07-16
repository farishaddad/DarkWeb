import type { AlertSummary } from '../types/api'
import type { AlertFilters } from '../types/filters'
import type { Severity } from '../types/models'

const SEVERITY_ORDER: Record<Severity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

function compareField(
  a: AlertSummary,
  b: AlertSummary,
  sortBy: AlertFilters['sortBy']
): number {
  switch (sortBy) {
    case 'severity':
      return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
    case 'category':
      return a.category.localeCompare(b.category)
    case 'created_at':
      return a.createdAt.localeCompare(b.createdAt)
  }
}

export function applyFilters(
  alerts: AlertSummary[],
  filters: AlertFilters
): AlertSummary[] {
  let filtered = alerts

  if (filters.categories.length > 0) {
    filtered = filtered.filter((a) => filters.categories.includes(a.category))
  }

  if (filters.severities.length > 0) {
    filtered = filtered.filter((a) => filters.severities.includes(a.severity))
  }

  if (filters.tiers.length > 0) {
    filtered = filtered.filter((a) => filters.tiers.includes(a.tier))
  }

  if (filters.timeRange.from) {
    filtered = filtered.filter((a) => a.createdAt >= filters.timeRange.from)
  }

  if (filters.timeRange.to) {
    filtered = filtered.filter((a) => a.createdAt <= filters.timeRange.to)
  }

  if (filters.searchText) {
    const search = filters.searchText.toLowerCase()
    filtered = filtered.filter(
      (a) =>
        a.ttpDescription.toLowerCase().includes(search) ||
        a.affectedInstitutions.some((i) => i.toLowerCase().includes(search))
    )
  }

  // Sort the result
  const sorted = [...filtered].sort((a, b) => {
    const cmp = compareField(a, b, filters.sortBy)
    return filters.sortOrder === 'asc' ? cmp : -cmp
  })

  return sorted
}
