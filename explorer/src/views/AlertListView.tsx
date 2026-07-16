import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAppStore } from '../store'
import type { FraudCategory, IntelligenceTier, Severity } from '../types'

const SEVERITY_OPTIONS: Severity[] = ['critical', 'high', 'medium', 'low']
const TIER_OPTIONS: IntelligenceTier[] = ['ttp', 'indicator', 'observable']
const CATEGORY_OPTIONS: FraudCategory[] = [
  'mfa_bypass',
  'synthetic_identity',
  'phishing_kit',
  'cnp_fraud',
  'account_takeover',
  'new_account_fraud',
  'recurring_billing_fraud',
  'money_mule',
  'investment_fraud',
  'social_engineering',
]

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-400 text-gray-900',
  low: 'bg-green-500 text-white',
}

function formatCategory(cat: string): string {
  return cat
    .split('_')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ')
}

function truncate(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text
  return text.slice(0, maxLen) + '…'
}

export function AlertListView() {
  const navigate = useNavigate()
  const { loadAlerts, setFilters, setPage, alertList, filters, loading } =
    useAppStore()

  useEffect(() => {
    loadAlerts()
  }, [loadAlerts, filters])

  const handleCategoryToggle = (cat: FraudCategory) => {
    const current = filters.categories
    const updated = current.includes(cat)
      ? current.filter((c) => c !== cat)
      : [...current, cat]
    setFilters({ categories: updated })
  }

  const handleSeverityToggle = (sev: Severity) => {
    const current = filters.severities
    const updated = current.includes(sev)
      ? current.filter((s) => s !== sev)
      : [...current, sev]
    setFilters({ severities: updated })
  }

  const handleTierToggle = (tier: IntelligenceTier) => {
    const current = filters.tiers
    const updated = current.includes(tier)
      ? current.filter((t) => t !== tier)
      : [...current, tier]
    setFilters({ tiers: updated })
  }

  const handleSearchChange = (value: string) => {
    setFilters({ searchText: value })
  }

  const handleDateFromChange = (value: string) => {
    setFilters({ timeRange: { ...filters.timeRange, from: value } })
  }

  const handleDateToChange = (value: string) => {
    setFilters({ timeRange: { ...filters.timeRange, to: value } })
  }

  const handleSortByChange = (value: string) => {
    setFilters({ sortBy: value as 'created_at' | 'severity' | 'category' })
  }

  const handleSortOrderChange = (value: string) => {
    setFilters({ sortOrder: value as 'asc' | 'desc' })
  }

  const alerts = alertList?.alerts ?? []
  const totalCount = alertList?.totalCount ?? 0
  const currentPage = filters.page
  const pageSize = filters.pageSize
  const totalPages = Math.max(1, Math.ceil(totalCount / pageSize))

  return (
    <div className="flex h-full">
      {/* Left Sidebar - Filters */}
      <aside className="w-72 shrink-0 overflow-y-auto border-r border-gray-200 bg-gray-50 p-4">
        <h2 className="mb-4 text-sm font-semibold uppercase tracking-wide text-gray-500">
          Filters
        </h2>

        {/* Search */}
        <div className="mb-5">
          <label
            htmlFor="search-input"
            className="mb-1 block text-xs font-medium text-gray-700"
          >
            Search
          </label>
          <input
            id="search-input"
            type="text"
            placeholder="Search alerts…"
            value={filters.searchText}
            onChange={(e) => handleSearchChange(e.target.value)}
            className="w-full rounded border border-gray-300 px-2 py-1.5 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>

        {/* Date Range */}
        <div className="mb-5">
          <span className="mb-1 block text-xs font-medium text-gray-700">
            Date Range
          </span>
          <input
            type="date"
            aria-label="From date"
            value={filters.timeRange.from}
            onChange={(e) => handleDateFromChange(e.target.value)}
            className="mb-1 w-full rounded border border-gray-300 px-2 py-1 text-sm"
          />
          <input
            type="date"
            aria-label="To date"
            value={filters.timeRange.to}
            onChange={(e) => handleDateToChange(e.target.value)}
            className="w-full rounded border border-gray-300 px-2 py-1 text-sm"
          />
        </div>

        {/* Severity */}
        <div className="mb-5">
          <span className="mb-1 block text-xs font-medium text-gray-700">
            Severity
          </span>
          {SEVERITY_OPTIONS.map((sev) => (
            <label key={sev} className="flex items-center gap-2 py-0.5 text-sm">
              <input
                type="checkbox"
                checked={filters.severities.includes(sev)}
                onChange={() => handleSeverityToggle(sev)}
                className="rounded border-gray-300"
              />
              <span className="capitalize">{sev}</span>
            </label>
          ))}
        </div>

        {/* Tier */}
        <div className="mb-5">
          <span className="mb-1 block text-xs font-medium text-gray-700">
            Intelligence Tier
          </span>
          {TIER_OPTIONS.map((tier) => (
            <label key={tier} className="flex items-center gap-2 py-0.5 text-sm">
              <input
                type="checkbox"
                checked={filters.tiers.includes(tier)}
                onChange={() => handleTierToggle(tier)}
                className="rounded border-gray-300"
              />
              <span className="capitalize">{tier}</span>
            </label>
          ))}
        </div>

        {/* Categories */}
        <div className="mb-5">
          <span className="mb-1 block text-xs font-medium text-gray-700">
            Category
          </span>
          {CATEGORY_OPTIONS.map((cat) => (
            <label key={cat} className="flex items-center gap-2 py-0.5 text-sm">
              <input
                type="checkbox"
                checked={filters.categories.includes(cat)}
                onChange={() => handleCategoryToggle(cat)}
                className="rounded border-gray-300"
              />
              <span>{formatCategory(cat)}</span>
            </label>
          ))}
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 overflow-y-auto p-6">
        {/* Header with sort controls */}
        <div className="mb-4 flex items-center justify-between">
          <h1 className="text-2xl font-bold text-gray-900">Alerts</h1>
          <div className="flex items-center gap-3">
            <label className="flex items-center gap-1 text-sm text-gray-600">
              Sort by
              <select
                value={filters.sortBy}
                onChange={(e) => handleSortByChange(e.target.value)}
                className="rounded border border-gray-300 px-2 py-1 text-sm"
              >
                <option value="created_at">Date</option>
                <option value="severity">Severity</option>
                <option value="category">Category</option>
              </select>
            </label>
            <label className="flex items-center gap-1 text-sm text-gray-600">
              Order
              <select
                value={filters.sortOrder}
                onChange={(e) => handleSortOrderChange(e.target.value)}
                className="rounded border border-gray-300 px-2 py-1 text-sm"
              >
                <option value="desc">Desc</option>
                <option value="asc">Asc</option>
              </select>
            </label>
          </div>
        </div>

        {/* Loading state */}
        {loading.alerts && (
          <div className="flex items-center justify-center py-12">
            <p className="text-gray-500">Loading alerts…</p>
          </div>
        )}

        {/* Empty state */}
        {!loading.alerts && alerts.length === 0 && (
          <div className="flex items-center justify-center py-12">
            <p className="text-gray-500">No alerts found matching your filters.</p>
          </div>
        )}

        {/* Alert Cards Grid */}
        {!loading.alerts && alerts.length > 0 && (
          <>
            <div className="grid gap-4 sm:grid-cols-1 md:grid-cols-2 lg:grid-cols-3">
              {alerts.map((alert) => (
                <button
                  key={alert.alertId}
                  type="button"
                  onClick={() => navigate(`/alerts/${alert.alertId}`)}
                  className="cursor-pointer rounded-lg border border-gray-200 bg-white p-4 text-left shadow-sm transition hover:shadow-md"
                >
                  <div className="mb-2 flex items-center justify-between">
                    <span
                      className={`inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase ${SEVERITY_COLORS[alert.severity]}`}
                    >
                      {alert.severity}
                    </span>
                    <span className="text-xs text-gray-400">
                      {new Date(alert.createdAt).toLocaleDateString()}
                    </span>
                  </div>
                  <p className="mb-1 text-sm font-medium text-gray-800">
                    {formatCategory(alert.category)}
                  </p>
                  <p className="mb-2 text-sm text-gray-600">
                    {truncate(alert.ttpDescription, 100)}
                  </p>
                  {alert.affectedInstitutions.length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      {alert.affectedInstitutions.map((inst) => (
                        <span
                          key={inst}
                          className="rounded bg-blue-100 px-1.5 py-0.5 text-xs text-blue-800"
                        >
                          {inst}
                        </span>
                      ))}
                    </div>
                  )}
                </button>
              ))}
            </div>

            {/* Pagination */}
            <div className="mt-6 flex items-center justify-between">
              <p className="text-sm text-gray-600">
                Page {currentPage} of {totalPages} ({totalCount} total)
              </p>
              <div className="flex gap-2">
                <button
                  type="button"
                  disabled={currentPage <= 1}
                  onClick={() => setPage(currentPage - 1)}
                  className="rounded border border-gray-300 px-3 py-1 text-sm disabled:cursor-not-allowed disabled:opacity-50"
                >
                  Previous
                </button>
                <button
                  type="button"
                  disabled={currentPage >= totalPages}
                  onClick={() => setPage(currentPage + 1)}
                  className="rounded border border-gray-300 px-3 py-1 text-sm disabled:cursor-not-allowed disabled:opacity-50"
                >
                  Next
                </button>
              </div>
            </div>
          </>
        )}
      </main>
    </div>
  )
}
