import { useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useAppStore } from '../store/appStore'
import { groupTagsByNamespace } from '../utils/tags'
import type { Severity, DetectionRule, MachineTag, GalaxyMatch, ProcessingStep } from '../types'

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-400 text-gray-900',
  low: 'bg-green-500 text-white',
}

const RULE_TYPE_COLORS: Record<DetectionRule['ruleType'], string> = {
  yara: 'bg-purple-100 text-purple-800',
  sigma: 'bg-blue-100 text-blue-800',
  custom: 'bg-gray-100 text-gray-800',
}

const TAG_NAMESPACE_COLORS: Record<string, string> = {
  'mitre-attack': 'bg-red-100 text-red-800',
  'dark-web-fraud': 'bg-indigo-100 text-indigo-800',
  'tlp': 'bg-amber-100 text-amber-800',
  'misp-galaxy': 'bg-emerald-100 text-emerald-800',
}

const PROVENANCE_STEPS = [
  'CrawlingEngine',
  'ContentAnalyst',
  'DataStructurer',
  'TaggingEngine',
  'AlertGenerator',
]

function getTagColor(namespace: string): string {
  return TAG_NAMESPACE_COLORS[namespace] ?? 'bg-gray-100 text-gray-700'
}

export function AlertDetailView() {
  const { alertId } = useParams<{ alertId: string }>()
  const { currentAlert, loading, error, loadAlertDetail, loadSignalSources } = useAppStore()

  useEffect(() => {
    if (alertId) {
      loadAlertDetail(alertId)
      loadSignalSources(alertId)
    }
  }, [alertId, loadAlertDetail, loadSignalSources])

  if (loading.detail) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="flex flex-col items-center gap-3">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-gray-300 border-t-indigo-600" />
          <p className="text-sm text-gray-500">Loading alert details...</p>
        </div>
      </div>
    )
  }

  if (error || !currentAlert) {
    return (
      <div className="p-6">
        <div className="rounded-lg border border-red-200 bg-red-50 p-6 text-center">
          <h2 className="text-lg font-semibold text-red-800">Alert not found</h2>
          <p className="mt-2 text-sm text-red-600">
            The alert with ID &quot;{alertId}&quot; could not be found.
          </p>
          <Link
            to="/alerts"
            className="mt-4 inline-block rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700"
          >
            Back to Alerts
          </Link>
        </div>
      </div>
    )
  }

  const groupedTags = groupTagsByNamespace(currentAlert.tags)

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3">
            <span
              className={`inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold uppercase ${SEVERITY_COLORS[currentAlert.severity]}`}
            >
              {currentAlert.severity}
            </span>
            <span className="text-sm font-medium text-gray-500">{currentAlert.alertType}</span>
          </div>
          <h1 className="mt-2 text-2xl font-bold text-gray-900">{currentAlert.ttpDescription}</h1>
          <p className="mt-1 text-sm text-gray-500">
            Created: {new Date(currentAlert.createdAt).toLocaleString()}
          </p>
        </div>
        <Link
          to={`/alerts/${alertId}/sources`}
          className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700"
        >
          View Signal Sources
        </Link>
      </div>

      {/* Affected Institutions */}
      <div>
        <h2 className="text-sm font-semibold text-gray-700 mb-2">Affected Institutions</h2>
        <div className="flex flex-wrap gap-2">
          {currentAlert.affectedInstitutions.map((institution) => (
            <span
              key={institution}
              className="inline-flex items-center rounded-full bg-blue-100 px-3 py-1 text-xs font-medium text-blue-800"
            >
              {institution}
            </span>
          ))}
        </div>
      </div>

      {/* Provenance Chain */}
      <div className="rounded-lg border border-gray-200 bg-white p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Provenance Chain</h2>
        <ProvenanceChainStepper steps={currentAlert.provenance.processingChain} />
      </div>

      {/* Detection Rules */}
      {currentAlert.detectionRules.length > 0 && (
        <div className="rounded-lg border border-gray-200 bg-white p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Detection Rules</h2>
          <div className="space-y-4">
            {currentAlert.detectionRules.map((rule, idx) => (
              <DetectionRuleBlock key={idx} rule={rule} />
            ))}
          </div>
        </div>
      )}

      {/* Machine Tags */}
      {currentAlert.tags.length > 0 && (
        <div className="rounded-lg border border-gray-200 bg-white p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Machine Tags</h2>
          <div className="space-y-3">
            {Object.entries(groupedTags).map(([namespace, tags]) => (
              <TagNamespaceGroup key={namespace} namespace={namespace} tags={tags} />
            ))}
          </div>
        </div>
      )}

      {/* Galaxy Match */}
      {currentAlert.galaxyMatch && (
        <GalaxyMatchCard galaxyMatch={currentAlert.galaxyMatch} />
      )}
    </div>
  )
}

function ProvenanceChainStepper({ steps }: { steps: ProcessingStep[] }) {
  // Map steps to the expected 5-step pipeline order
  const stepMap = new Map(steps.map((s) => [s.agentName, s]))

  return (
    <div className="relative">
      {PROVENANCE_STEPS.map((stepName, idx) => {
        const step = stepMap.get(stepName)
        const isLast = idx === PROVENANCE_STEPS.length - 1

        return (
          <div key={stepName} className="flex gap-4">
            {/* Vertical line + dot */}
            <div className="flex flex-col items-center">
              <div
                className={`flex h-8 w-8 items-center justify-center rounded-full text-xs font-bold ${
                  step ? 'bg-indigo-600 text-white' : 'bg-gray-300 text-gray-600'
                }`}
              >
                {idx + 1}
              </div>
              {!isLast && (
                <div className="w-0.5 flex-1 bg-gray-300 min-h-[24px]" />
              )}
            </div>

            {/* Content */}
            <div className={`pb-6 ${isLast ? 'pb-0' : ''}`}>
              <p className="text-sm font-semibold text-gray-900">{stepName}</p>
              {step && (
                <>
                  <p className="text-xs text-gray-500 mt-0.5">
                    {new Date(step.timestamp).toLocaleString()}
                  </p>
                  <p className="text-sm text-gray-600 mt-1">{step.summary}</p>
                </>
              )}
              {!step && (
                <p className="text-xs text-gray-400 mt-0.5">No data available</p>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}

function DetectionRuleBlock({ rule }: { rule: DetectionRule }) {
  return (
    <div className="rounded-md border border-gray-200">
      <div className="flex items-center gap-2 px-4 py-2 bg-gray-50 border-b border-gray-200">
        <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${RULE_TYPE_COLORS[rule.ruleType]}`}>
          {rule.ruleType}
        </span>
        <span className="text-xs text-gray-500">
          Confidence: {(rule.confidence * 100).toFixed(0)}%
        </span>
      </div>
      <pre className="p-4 text-xs text-gray-800 overflow-x-auto bg-gray-900 text-green-300 rounded-b-md">
        <code>{rule.ruleContent}</code>
      </pre>
    </div>
  )
}

function TagNamespaceGroup({ namespace, tags }: { namespace: string; tags: MachineTag[] }) {
  const colorClass = getTagColor(namespace)

  return (
    <div>
      <p className="text-xs font-semibold text-gray-500 uppercase mb-1">{namespace}</p>
      <div className="flex flex-wrap gap-1.5">
        {tags.map((tag, idx) => (
          <span
            key={`${tag.predicate}-${tag.value}-${idx}`}
            className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${colorClass}`}
          >
            {tag.predicate}={tag.value}
          </span>
        ))}
      </div>
    </div>
  )
}

function GalaxyMatchCard({ galaxyMatch }: { galaxyMatch: GalaxyMatch }) {
  const mitreUrl = `https://attack.mitre.org/techniques/${galaxyMatch.clusterValue.replace('.', '/')}/`

  return (
    <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-6">
      <h2 className="text-lg font-semibold text-emerald-900 mb-3">Galaxy Match</h2>
      <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
        <div>
          <dt className="font-medium text-gray-600">Galaxy</dt>
          <dd className="text-gray-900">{galaxyMatch.galaxy}</dd>
        </div>
        <div>
          <dt className="font-medium text-gray-600">Cluster Value</dt>
          <dd className="text-gray-900">{galaxyMatch.clusterValue}</dd>
        </div>
        <div>
          <dt className="font-medium text-gray-600">Cluster UUID</dt>
          <dd className="text-gray-900 font-mono text-xs">{galaxyMatch.clusterUuid}</dd>
        </div>
        <div>
          <dt className="font-medium text-gray-600">Source</dt>
          <dd className="text-gray-900">{galaxyMatch.source}</dd>
        </div>
      </dl>
      <a
        href={mitreUrl}
        target="_blank"
        rel="noopener noreferrer"
        className="mt-4 inline-flex items-center gap-1 text-sm font-medium text-emerald-700 hover:text-emerald-800"
      >
        View MITRE Reference →
      </a>
    </div>
  )
}
