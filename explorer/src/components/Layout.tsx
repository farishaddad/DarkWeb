import { NavLink, Outlet } from 'react-router-dom'
import { APP_CONFIG } from '../config'

const navItems = [
  { to: '/', label: 'Dashboard', icon: '📊' },
  { to: '/alerts', label: 'Alerts', icon: '🚨' },
  { to: '/graph', label: 'Graph', icon: '🕸️' },
]

export function Layout() {
  return (
    <div className="flex min-h-screen bg-gray-50">
      <aside className="w-64 bg-gray-900 text-white flex flex-col">
        <div className="p-4 border-b border-gray-700">
          <h1 className="text-lg font-bold">Fraud Intelligence</h1>
          <p className="text-xs text-gray-400 mt-1">Explorer</p>
        </div>
        <nav className="flex-1 p-4 space-y-1">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-gray-700 text-white'
                    : 'text-gray-300 hover:bg-gray-800 hover:text-white'
                }`
              }
            >
              <span>{item.icon}</span>
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="p-4 border-t border-gray-700">
          <DataModeBadge />
          <p className="text-xs text-gray-500 mt-2">Dark Web Fraud Agent</p>
        </div>
      </aside>
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  )
}

function DataModeBadge() {
  const isLive = APP_CONFIG.dataMode === 'live'

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-full text-xs font-medium ${
        isLive
          ? 'bg-green-900/50 text-green-300 border border-green-700'
          : 'bg-yellow-900/50 text-yellow-300 border border-yellow-700'
      }`}
    >
      <span
        className={`w-1.5 h-1.5 rounded-full ${
          isLive ? 'bg-green-400' : 'bg-yellow-400'
        }`}
      />
      {isLive ? 'Live' : 'Mock'} Data
    </span>
  )
}
