import type { Severity } from './models'

export interface GraphNode {
  id: string
  type: 'alert' | 'institution' | 'ttp' | 'entity' | 'campaign'
  label: string
  severity?: Severity
  metadata?: Record<string, string>
}

export interface GraphEdge {
  source: string
  target: string
  relationship: string
  weight: number
}

export interface RelationshipGraph {
  nodes: GraphNode[]
  edges: GraphEdge[]
}
