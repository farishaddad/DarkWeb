import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { useAppStore } from '../store/appStore'
import { redactUrl } from '../utils/redaction'
import type { SignalSource } from '../types'

function confidenceColor(confidence: number): string {
  if (confidence < 0.5) return 'bg-red-500'
  if (confidence < 0.8) return 'bg-yellow-500'
  return 'bg-green-500'
}

function guardRailBadgeClasses(result: SignalSource['guardRailResult']): string {
  switch (result) {
    case 'PASSED':
      return 'bg-green-100 text-green-800 border-green-300'
    case 'FILTERED':
      return 'bg-yellow-100 text-yellow-800 border-yellow-300'
    case 'FLAGGED':
      return 'bg-red-100 text-red-800 border-red-300'
  }
}

function sourceTypeBadgeClasses(sourceType: string): string {
  switch (sourceType) {
    case 'tor_hidden_service':
      return 'bg-purple-100 text-purple-800'
    case 'i2p_site':
      return 'bg-indigo-100 text-indigo-800'
    case 'telegram_channel':
      return 'bg-blue-100 text-blue-800'
    case 'forum_post':
      return 'bg-gray-100 text-gray-800'
    case 'marketplace':
      return 'bg-orange-100 text-orange-800'
    default:
      return 'bg-gray-100 text-gray-800'
  }
}

function formatSourceType(sourceType: string): string {
  return sourceType.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

export function SignalSourcesView() {
  const { alertId } = useParams<{ alertId: string }>()
  const { signalSources, loading, loadSignalSources } = useAppStore()
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set())

  useEffect(() => {
    if (alertId) {
      loadSignalSources(alertId)
    }
  }, [alertId, loadSignalSources])

  const toggleExpand = (sourceId: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev)
      if (next.has(sourceId)) {
        next.delete(sourceId)
      } else {
        next.add(sourceId)
      }
      return next
    })
  }

  if (loading.sources) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900" />
      </div>
    )
  }

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold text-gray-900">Signal Sources</h1>
      <p className="mt-2 text-gray-600 mb-6">
        Sources contributing to alert: <span className="font-mono text-sm">{alertId}</span>
      </p>

      {signalSources.length === 0 && (
        <p className="text-gray-500">No signal sources found for this alert.</p>
      )}

      <div className="space-y-4">
        {signalSources.map((source) => {
          const isExpanded = expandedIds.has(source.sourceId)
          return (
            <div
              key={source.sourceId}
              className="border border-gray-200 rounded-lg bg-white shadow-sm"
            >
              {/* Header */}
              <button
                type="button"
                onClick={() => toggleExpand(source.sourceId)}
                className="w-full px-4 py-3 flex items-center justify-between text-left hover:bg-gray-50 rounded-t-lg"
              >
                <div className="flex items-center gap-3 flex-wrap">
                  {/* Source type badge */}
                  <span
                    className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${sourceTypeBadgeClasses(source.sourceType)}`}
                  >
                    {formatSourceType(source.sourceType)}
                  </span>

                  {/* Redacted URL */}
                  <span className="text-sm text-gray-700 font-mono">
                    {redactUrl(source.sourceUrl)}
                  </span>

                  {/* Crawl timestamp */}
                  <span className="text-xs text-gray-500">
                    {new Date(source.crawlTimestamp).toLocaleString()}
                  </span>
                </div>

                {/* Expand/collapse indicator */}
                <span className="text-gray-400 text-sm ml-2">
                  {isExpanded ? '▲' : '▼'}
                </span>
              </button>

              {/* Confidence bar and guardrail badge */}
              <div className="px-4 pb-3 flex items-center gap-4">
                {/* Confidence bar */}
                <div className="flex items-center gap-2 flex-1">
                  <span className="text-xs text-gray-500 w-20">Confidence:</span>
                  <div className="flex-1 h-2 bg-gray-200 rounded-full max-w-xs">
                    <div
                      className={`h-2 rounded-full ${confidenceColor(source.confidence)}`}
                      style={{ width: `${source.confidence * 100}%` }}
                    />
                  </div>
                  <span className="text-xs text-gray-600 w-10 text-right">
                    {(source.confidence * 100).toFixed(0)}%
                  </span>
                </div>

                {/* GuardRail badge */}
                <span
                  className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${guardRailBadgeClasses(source.guardRailResult)}`}
                >
                  {source.guardRailResult}
                </span>
              </div>

              {/* Expanded section: extracted entities */}
              {isExpanded && (
                <div className="px-4 pb-4 border-t border-gray-100 pt-3">
                  <h4 className="text-sm font-medium text-gray-700 mb-2">
                    Extracted Entities ({source.entities.length})
                  </h4>
                  {source.entities.length === 0 ? (
                    <p className="text-xs text-gray-500">No entities extracted.</p>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="min-w-full text-xs">
                        <thead>
                          <tr className="border-b border-gray-200">
                            <th className="text-left py-1 pr-4 font-medium text-gray-600">
                              Type
                            </th>
                            <th className="text-left py-1 pr-4 font-medium text-gray-600">
                              Value
                            </th>
                            <th className="text-left py-1 font-medium text-gray-600">
                              Confidence
                            </th>
                          </tr>
                        </thead>
                        <tbody>
                          {source.entities.map((entity, idx) => (
                            <tr
                              key={`${entity.entityType}-${entity.value}-${idx}`}
                              className="border-b border-gray-50"
                            >
                              <td className="py-1 pr-4">
                                <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-gray-100 text-gray-700 font-mono">
                                  {entity.entityType}
                                </span>
                              </td>
                              <td className="py-1 pr-4 text-gray-800">
                                {entity.value}
                              </td>
                              <td className="py-1">
                                <div className="flex items-center gap-1">
                                  <div className="w-16 h-1.5 bg-gray-200 rounded-full">
                                    <div
                                      className={`h-1.5 rounded-full ${confidenceColor(entity.confidence)}`}
                                      style={{
                                        width: `${entity.confidence * 100}%`,
                                      }}
                                    />
                                  </div>
                                  <span className="text-gray-500">
                                    {(entity.confidence * 100).toFixed(0)}%
                                  </span>
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
