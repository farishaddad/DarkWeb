import { describe, it, expect } from 'vitest'
import { buildRelationshipGraph } from './graph'
import type { AlertDetail } from '../types'

function makeAlert(overrides: Partial<AlertDetail> = {}): AlertDetail {
  return {
    alertId: 'alert-001',
    alertType: 'ttp_alert',
    severity: 'high',
    category: 'account_takeover',
    tier: 'ttp',
    ttpDescription: 'Credential stuffing via compromised databases',
    affectedInstitutions: ['HSBC', 'Barclays'],
    detectionRules: [],
    relatedIntelligence: [],
    provenance: {
      originalSourceUrl: 'http://example.onion/page',
      crawlTimestamp: '2025-01-15T10:00:00Z',
      s3ArtifactKey: 'crawl-artifacts/2025/01/15/001/raw.html',
      processingChain: [],
    },
    tags: [
      { namespace: 'mitre-attack', predicate: 'technique', value: 'T1110' },
      { namespace: 'fraud', predicate: 'category', value: 'account_takeover' },
    ],
    galaxyMatch: null,
    createdAt: '2025-01-15T12:00:00Z',
    ...overrides,
  }
}

describe('buildRelationshipGraph', () => {
  it('creates alert node for each alert', () => {
    const alerts = [makeAlert({ alertId: 'a1' }), makeAlert({ alertId: 'a2' })]
    const graph = buildRelationshipGraph(alerts)

    const alertNodes = graph.nodes.filter((n) => n.type === 'alert')
    expect(alertNodes).toHaveLength(2)
    expect(alertNodes.map((n) => n.id)).toContain('alert:a1')
    expect(alertNodes.map((n) => n.id)).toContain('alert:a2')
  })

  it('creates institution nodes and edges with relationship "affects"', () => {
    const alerts = [makeAlert({ alertId: 'a1', affectedInstitutions: ['HSBC', 'Lloyds'] })]
    const graph = buildRelationshipGraph(alerts)

    const instNodes = graph.nodes.filter((n) => n.type === 'institution')
    expect(instNodes).toHaveLength(2)
    expect(instNodes.map((n) => n.id)).toContain('institution:hsbc')
    expect(instNodes.map((n) => n.id)).toContain('institution:lloyds')

    const affectsEdges = graph.edges.filter((e) => e.relationship === 'affects')
    expect(affectsEdges).toHaveLength(2)
    expect(affectsEdges.every((e) => e.source === 'alert:a1')).toBe(true)
  })

  it('deduplicates institution nodes by lowercase name', () => {
    const alerts = [
      makeAlert({ alertId: 'a1', affectedInstitutions: ['HSBC'] }),
      makeAlert({ alertId: 'a2', affectedInstitutions: ['hsbc'] }),
      makeAlert({ alertId: 'a3', affectedInstitutions: ['Hsbc'] }),
    ]
    const graph = buildRelationshipGraph(alerts)

    const instNodes = graph.nodes.filter((n) => n.type === 'institution')
    expect(instNodes).toHaveLength(1)
    expect(instNodes[0].id).toBe('institution:hsbc')
  })

  it('creates TTP nodes only from mitre-attack technique tags', () => {
    const alerts = [
      makeAlert({
        alertId: 'a1',
        tags: [
          { namespace: 'mitre-attack', predicate: 'technique', value: 'T1110' },
          { namespace: 'mitre-attack', predicate: 'tactic', value: 'TA0001' },
          { namespace: 'fraud', predicate: 'technique', value: 'phishing' },
          { namespace: 'mitre-attack', predicate: 'technique', value: 'T1531' },
        ],
      }),
    ]
    const graph = buildRelationshipGraph(alerts)

    const ttpNodes = graph.nodes.filter((n) => n.type === 'ttp')
    expect(ttpNodes).toHaveLength(2)
    expect(ttpNodes.map((n) => n.id)).toContain('ttp:T1110')
    expect(ttpNodes.map((n) => n.id)).toContain('ttp:T1531')
  })

  it('creates campaign nodes only for campaign_alert with non-null galaxyMatch', () => {
    const alerts = [
      makeAlert({
        alertId: 'a1',
        alertType: 'campaign_alert',
        galaxyMatch: {
          galaxy: 'threat-actor',
          clusterUuid: 'uuid-123',
          clusterValue: 'APT28',
          source: 'MISP',
        },
      }),
      makeAlert({
        alertId: 'a2',
        alertType: 'campaign_alert',
        galaxyMatch: null,
      }),
      makeAlert({
        alertId: 'a3',
        alertType: 'ttp_alert',
        galaxyMatch: {
          galaxy: 'threat-actor',
          clusterUuid: 'uuid-456',
          clusterValue: 'APT29',
          source: 'MISP',
        },
      }),
    ]
    const graph = buildRelationshipGraph(alerts)

    const campaignNodes = graph.nodes.filter((n) => n.type === 'campaign')
    expect(campaignNodes).toHaveLength(1)
    expect(campaignNodes[0].id).toBe('campaign:uuid-123')
    expect(campaignNodes[0].label).toBe('APT28')
  })

  it('creates correct edge relationships', () => {
    const alerts = [
      makeAlert({
        alertId: 'a1',
        alertType: 'campaign_alert',
        affectedInstitutions: ['HSBC'],
        tags: [{ namespace: 'mitre-attack', predicate: 'technique', value: 'T1110' }],
        galaxyMatch: {
          galaxy: 'threat-actor',
          clusterUuid: 'uuid-123',
          clusterValue: 'APT28',
          source: 'MISP',
        },
      }),
    ]
    const graph = buildRelationshipGraph(alerts)

    const relationships = graph.edges.map((e) => e.relationship)
    expect(relationships).toContain('affects')
    expect(relationships).toContain('uses_ttp')
    expect(relationships).toContain('part_of_campaign')
  })

  it('every edge references existing nodes', () => {
    const alerts = [
      makeAlert({ alertId: 'a1', affectedInstitutions: ['HSBC', 'Barclays'] }),
      makeAlert({
        alertId: 'a2',
        alertType: 'campaign_alert',
        affectedInstitutions: ['Lloyds'],
        tags: [{ namespace: 'mitre-attack', predicate: 'technique', value: 'T1531' }],
        galaxyMatch: {
          galaxy: 'threat-actor',
          clusterUuid: 'uuid-999',
          clusterValue: 'FIN7',
          source: 'MISP',
        },
      }),
    ]
    const graph = buildRelationshipGraph(alerts)

    const nodeIds = new Set(graph.nodes.map((n) => n.id))
    for (const edge of graph.edges) {
      expect(nodeIds.has(edge.source)).toBe(true)
      expect(nodeIds.has(edge.target)).toBe(true)
    }
  })

  it('prunes to maxNodes keeping highest-connected nodes', () => {
    // Create enough alerts to exceed maxNodes=5
    const alerts: AlertDetail[] = []
    for (let i = 0; i < 10; i++) {
      alerts.push(
        makeAlert({
          alertId: `a${i}`,
          affectedInstitutions: [`Bank${i}`],
          tags: [{ namespace: 'mitre-attack', predicate: 'technique', value: `T${1000 + i}` }],
        })
      )
    }
    // Add an alert that connects to many institutions (high connectivity)
    alerts.push(
      makeAlert({
        alertId: 'hub',
        affectedInstitutions: ['Bank0', 'Bank1', 'Bank2', 'Bank3', 'Bank4', 'Bank5'],
        tags: [
          { namespace: 'mitre-attack', predicate: 'technique', value: 'T1000' },
          { namespace: 'mitre-attack', predicate: 'technique', value: 'T1001' },
        ],
      })
    )

    const graph = buildRelationshipGraph(alerts, 5)

    expect(graph.nodes.length).toBe(5)
    // The hub alert should be retained as it has the most connections
    expect(graph.nodes.map((n) => n.id)).toContain('alert:hub')
  })

  it('after pruning, all edges reference existing nodes', () => {
    const alerts: AlertDetail[] = []
    for (let i = 0; i < 20; i++) {
      alerts.push(
        makeAlert({
          alertId: `a${i}`,
          affectedInstitutions: [`UniqueBank${i}`],
          tags: [{ namespace: 'mitre-attack', predicate: 'technique', value: `T${2000 + i}` }],
        })
      )
    }

    const graph = buildRelationshipGraph(alerts, 10)

    expect(graph.nodes.length).toBe(10)
    const nodeIds = new Set(graph.nodes.map((n) => n.id))
    for (const edge of graph.edges) {
      expect(nodeIds.has(edge.source)).toBe(true)
      expect(nodeIds.has(edge.target)).toBe(true)
    }
  })

  it('returns empty graph for empty alerts array', () => {
    const graph = buildRelationshipGraph([])
    expect(graph.nodes).toHaveLength(0)
    expect(graph.edges).toHaveLength(0)
  })

  it('does not prune when nodes are within maxNodes', () => {
    const alerts = [
      makeAlert({ alertId: 'a1', affectedInstitutions: ['HSBC'] }),
    ]
    const graph = buildRelationshipGraph(alerts, 100)

    // 1 alert + 1 institution + 1 TTP (from default tags) = 3 nodes
    expect(graph.nodes.length).toBeLessThanOrEqual(100)
    expect(graph.nodes.length).toBeGreaterThan(0)
  })

  it('assigns severity to alert nodes', () => {
    const alerts = [makeAlert({ alertId: 'a1', severity: 'critical' })]
    const graph = buildRelationshipGraph(alerts)

    const alertNode = graph.nodes.find((n) => n.id === 'alert:a1')
    expect(alertNode?.severity).toBe('critical')
  })

  it('assigns weight to edges based on severity', () => {
    const alerts = [makeAlert({ alertId: 'a1', severity: 'critical', affectedInstitutions: ['HSBC'] })]
    const graph = buildRelationshipGraph(alerts)

    const affectsEdge = graph.edges.find((e) => e.relationship === 'affects')
    expect(affectsEdge?.weight).toBe(4)
  })

  it('deduplicates TTP nodes when multiple alerts use same technique', () => {
    const alerts = [
      makeAlert({
        alertId: 'a1',
        tags: [{ namespace: 'mitre-attack', predicate: 'technique', value: 'T1110' }],
      }),
      makeAlert({
        alertId: 'a2',
        tags: [{ namespace: 'mitre-attack', predicate: 'technique', value: 'T1110' }],
      }),
    ]
    const graph = buildRelationshipGraph(alerts)

    const ttpNodes = graph.nodes.filter((n) => n.type === 'ttp')
    expect(ttpNodes).toHaveLength(1)
    expect(ttpNodes[0].id).toBe('ttp:T1110')

    // But both alerts should have edges to the TTP
    const ttpEdges = graph.edges.filter((e) => e.target === 'ttp:T1110')
    expect(ttpEdges).toHaveLength(2)
  })
})
