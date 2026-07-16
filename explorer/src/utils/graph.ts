import type { AlertDetail, RelationshipGraph, GraphNode, GraphEdge } from '../types'

const SEVERITY_WEIGHTS: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
}

function severityWeight(severity: string): number {
  return SEVERITY_WEIGHTS[severity] ?? 1
}

export function buildRelationshipGraph(
  alerts: AlertDetail[],
  maxNodes: number = 100
): RelationshipGraph {
  const nodes: Map<string, GraphNode> = new Map()
  const edges: GraphEdge[] = []

  for (const alert of alerts) {
    // Add alert node
    const alertNodeId = `alert:${alert.alertId}`
    nodes.set(alertNodeId, {
      id: alertNodeId,
      type: 'alert',
      label: alert.ttpDescription.substring(0, 40),
      severity: alert.severity,
    })

    // Add institution nodes and edges
    for (const institution of alert.affectedInstitutions) {
      const instNodeId = `institution:${institution.toLowerCase()}`
      if (!nodes.has(instNodeId)) {
        nodes.set(instNodeId, {
          id: instNodeId,
          type: 'institution',
          label: institution,
        })
      }
      edges.push({
        source: alertNodeId,
        target: instNodeId,
        relationship: 'affects',
        weight: severityWeight(alert.severity),
      })
    }

    // Add TTP nodes from tags where namespace='mitre-attack' && predicate='technique'
    for (const tag of alert.tags) {
      if (tag.namespace === 'mitre-attack' && tag.predicate === 'technique') {
        const ttpNodeId = `ttp:${tag.value}`
        if (!nodes.has(ttpNodeId)) {
          nodes.set(ttpNodeId, {
            id: ttpNodeId,
            type: 'ttp',
            label: `ATT&CK ${tag.value}`,
          })
        }
        edges.push({
          source: alertNodeId,
          target: ttpNodeId,
          relationship: 'uses_ttp',
          weight: 1,
        })
      }
    }

    // Add campaign nodes when alertType='campaign_alert' && galaxyMatch not null
    if (alert.alertType === 'campaign_alert' && alert.galaxyMatch) {
      const campaignNodeId = `campaign:${alert.galaxyMatch.clusterUuid}`
      if (!nodes.has(campaignNodeId)) {
        nodes.set(campaignNodeId, {
          id: campaignNodeId,
          type: 'campaign',
          label: alert.galaxyMatch.clusterValue,
        })
      }
      edges.push({
        source: alertNodeId,
        target: campaignNodeId,
        relationship: 'part_of_campaign',
        weight: 2,
      })
    }
  }

  // Prune to maxNodes if necessary — keep highest-connected nodes
  const nodeArray = Array.from(nodes.values())
  if (nodeArray.length > maxNodes) {
    const connectionCount = new Map<string, number>()
    for (const edge of edges) {
      connectionCount.set(edge.source, (connectionCount.get(edge.source) ?? 0) + 1)
      connectionCount.set(edge.target, (connectionCount.get(edge.target) ?? 0) + 1)
    }

    // Sort by connection count descending
    const sorted = [...nodeArray].sort(
      (a, b) => (connectionCount.get(b.id) ?? 0) - (connectionCount.get(a.id) ?? 0)
    )

    const keepIds = new Set(sorted.slice(0, maxNodes).map((n) => n.id))

    return {
      nodes: sorted.filter((n) => keepIds.has(n.id)),
      edges: edges.filter((e) => keepIds.has(e.source) && keepIds.has(e.target)),
    }
  }

  return { nodes: nodeArray, edges }
}
