import { useEffect } from 'react'
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  LineChart,
  Line,
  CartesianGrid,
  ResponsiveContainer,
  Legend,
} from 'recharts'
import { useAppStore } from '../store/appStore'
import type { Severity } from '../types'

const SEVERITY_COLORS: Record<Severity, string> = {
  low: '#22c55e',
  medium: '#eab308',
  high: '#f97316',
  critical: '#ef4444',
}

const CATEGORY_COLOR = '#6366f1'

export function DashboardView() {
  const { dashboardSummary, loading, loadDashboard } = useAppStore()

  useEffect(() => {
    loadDashboard()
  }, [loadDashboard])

  if (loading.dashboard) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-10 w-10 border-4 border-indigo-500 border-t-transparent" />
      </div>
    )
  }

  if (!dashboardSummary) {
    return (
      <div className="p-6 text-gray-500">No dashboard data available.</div>
    )
  }

  const { totalAlerts, campaignCount, activeSourceCount, alertsBySeverity, alertsByCategory, timelineData, recentAlerts } = dashboardSummary

  // Prepare chart data
  const severityData = (Object.entries(alertsBySeverity) as [Severity, number][]).map(
    ([name, value]) => ({ name, value })
  )

  const categoryData = Object.entries(alertsByCategory).map(([name, value]) => ({
    name: name.replace(/_/g, ' '),
    value,
  }))

  const timelineChartData = timelineData.map((point) => ({
    date: point.timestamp.substring(5), // MM-DD
    count: point.count,
  }))

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>

      {/* KPI Tiles */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-white rounded-lg shadow p-5">
          <p className="text-sm text-gray-500">Total Alerts</p>
          <p className="mt-1 text-3xl font-semibold text-gray-900">{totalAlerts}</p>
        </div>
        <div className="bg-white rounded-lg shadow p-5">
          <p className="text-sm text-gray-500">Active Campaigns</p>
          <p className="mt-1 text-3xl font-semibold text-gray-900">{campaignCount}</p>
        </div>
        <div className="bg-white rounded-lg shadow p-5">
          <p className="text-sm text-gray-500">Active Sources</p>
          <p className="mt-1 text-3xl font-semibold text-gray-900">{activeSourceCount}</p>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Donut Chart */}
        <div className="bg-white rounded-lg shadow p-5">
          <h2 className="text-lg font-medium text-gray-900 mb-4">Severity Distribution</h2>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={severityData}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={90}
                label={({ name, value }) => `${name}: ${value}`}
              >
                {severityData.map((entry) => (
                  <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name as Severity]} />
                ))}
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Category Bar Chart */}
        <div className="bg-white rounded-lg shadow p-5">
          <h2 className="text-lg font-medium text-gray-900 mb-4">Category Breakdown</h2>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={categoryData} layout="vertical" margin={{ left: 80 }}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis type="number" />
              <YAxis type="category" dataKey="name" width={100} tick={{ fontSize: 11 }} />
              <Tooltip />
              <Bar dataKey="value" fill={CATEGORY_COLOR} radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Timeline */}
      <div className="bg-white rounded-lg shadow p-5">
        <h2 className="text-lg font-medium text-gray-900 mb-4">30-Day Activity Timeline</h2>
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={timelineChartData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="date" tick={{ fontSize: 11 }} />
            <YAxis allowDecimals={false} />
            <Tooltip />
            <Line type="monotone" dataKey="count" stroke="#6366f1" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Recent Alerts */}
      <div className="bg-white rounded-lg shadow p-5">
        <h2 className="text-lg font-medium text-gray-900 mb-4">Recent Alerts</h2>
        <div className="space-y-3">
          {recentAlerts.slice(0, 5).map((alert) => (
            <div key={alert.alertId} className="flex items-center justify-between border rounded-md p-3">
              <div className="flex items-center gap-3">
                <span
                  className={`inline-block px-2 py-0.5 rounded text-xs font-medium text-white ${severityBadgeClass(alert.severity)}`}
                >
                  {alert.severity}
                </span>
                <span className="text-sm text-gray-800 truncate max-w-xs">{alert.ttpDescription}</span>
              </div>
              <span className="text-xs text-gray-400">{alert.createdAt.substring(0, 10)}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function severityBadgeClass(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return 'bg-red-600'
    case 'high':
      return 'bg-orange-500'
    case 'medium':
      return 'bg-yellow-500'
    case 'low':
      return 'bg-green-500'
  }
}
