import { useEffect, useRef } from 'react'
import {
  forceSimulation,
  forceLink,
  forceManyBody,
  forceCenter,
  type SimulationNodeDatum,
  type SimulationLinkDatum,
} from 'd3-force'
import { useAppStore } from '../store/appStore'
import type { GraphNode, GraphEdge } from '../types'

interface SimNode extends SimulationNodeDatum {
  id: string
  type: GraphNode['type']
  label: string
}

interface SimLink extends SimulationLinkDatum<SimNode> {
  relationship: string
  weight: number
}

const NODE_COLORS: Record<GraphNode['type'], string> = {
  alert: '#ef4444',
  institution: '#3b82f6',
  ttp: '#f97316',
  entity: '#10b981',
  campaign: '#a855f7',
}

const NODE_RADIUS: Record<GraphNode['type'], number> = {
  alert: 8,
  institution: 10,
  ttp: 7,
  entity: 6,
  campaign: 9,
}

export function RelationshipGraphView() {
  const svgRef = useRef<SVGSVGElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const { relationships, loading, loadRelationships } = useAppStore()

  useEffect(() => {
    loadRelationships('alert-001')
  }, [loadRelationships])

  useEffect(() => {
    if (!relationships || !svgRef.current || !containerRef.current) return

    const svg = svgRef.current
    const container = containerRef.current
    const width = container.clientWidth || 800
    const height = container.clientHeight || 600

    svg.setAttribute('width', String(width))
    svg.setAttribute('height', String(height))

    // Clear previous content
    svg.innerHTML = ''

    const { nodes: graphNodes, edges: graphEdges } = relationships

    if (graphNodes.length === 0) return

    // Build simulation data
    const simNodes: SimNode[] = graphNodes.map((n) => ({
      id: n.id,
      type: n.type,
      label: n.label,
    }))

    const nodeMap = new Map(simNodes.map((n) => [n.id, n]))

    const simLinks: SimLink[] = graphEdges
      .filter((e: GraphEdge) => nodeMap.has(e.source) && nodeMap.has(e.target))
      .map((e: GraphEdge) => ({
        source: e.source,
        target: e.target,
        relationship: e.relationship,
        weight: e.weight,
      }))

    // Create SVG groups
    const edgeGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g')
    const nodeGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g')
    const labelGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g')
    svg.appendChild(edgeGroup)
    svg.appendChild(nodeGroup)
    svg.appendChild(labelGroup)

    // Create edge elements
    const lineElements: SVGLineElement[] = simLinks.map(() => {
      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line')
      line.setAttribute('stroke', '#9ca3af')
      line.setAttribute('stroke-width', '1.5')
      line.setAttribute('stroke-opacity', '0.6')
      edgeGroup.appendChild(line)
      return line
    })

    // Create node elements
    const circleElements: SVGCircleElement[] = simNodes.map((n) => {
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle')
      circle.setAttribute('r', String(NODE_RADIUS[n.type]))
      circle.setAttribute('fill', NODE_COLORS[n.type])
      circle.setAttribute('stroke', '#ffffff')
      circle.setAttribute('stroke-width', '1.5')
      nodeGroup.appendChild(circle)
      return circle
    })

    // Create label elements
    const textElements: SVGTextElement[] = simNodes.map((n) => {
      const text = document.createElementNS('http://www.w3.org/2000/svg', 'text')
      text.setAttribute('font-size', '10')
      text.setAttribute('fill', '#374151')
      text.setAttribute('text-anchor', 'middle')
      text.setAttribute('dy', String(NODE_RADIUS[n.type] + 12))
      text.textContent = n.label.length > 20 ? n.label.slice(0, 18) + '…' : n.label
      labelGroup.appendChild(text)
      return text
    })

    // Run simulation
    const simulation = forceSimulation<SimNode>(simNodes)
      .force(
        'link',
        forceLink<SimNode, SimLink>(simLinks).id((d) => d.id).distance(80)
      )
      .force('charge', forceManyBody().strength(-100))
      .force('center', forceCenter(width / 2, height / 2))

    simulation.on('tick', () => {
      lineElements.forEach((line, i) => {
        const link = simLinks[i]
        const source = link.source as SimNode
        const target = link.target as SimNode
        line.setAttribute('x1', String(source.x ?? 0))
        line.setAttribute('y1', String(source.y ?? 0))
        line.setAttribute('x2', String(target.x ?? 0))
        line.setAttribute('y2', String(target.y ?? 0))
      })

      circleElements.forEach((circle, i) => {
        const node = simNodes[i]
        circle.setAttribute('cx', String(node.x ?? 0))
        circle.setAttribute('cy', String(node.y ?? 0))
      })

      textElements.forEach((text, i) => {
        const node = simNodes[i]
        text.setAttribute('x', String(node.x ?? 0))
        text.setAttribute('y', String(node.y ?? 0))
      })
    })

    return () => {
      simulation.stop()
    }
  }, [relationships])

  return (
    <div className="p-6 flex flex-col h-full">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Relationship Graph</h1>
          <p className="mt-1 text-gray-600">Entity relationship visualization powered by d3-force.</p>
        </div>
        <div className="flex gap-3">
          {Object.entries(NODE_COLORS).map(([type, color]) => (
            <div key={type} className="flex items-center gap-1">
              <span
                className="inline-block w-3 h-3 rounded-full"
                style={{ backgroundColor: color }}
              />
              <span className="text-xs text-gray-600 capitalize">{type}</span>
            </div>
          ))}
        </div>
      </div>

      {loading.graph && (
        <div className="flex items-center justify-center py-12">
          <p className="text-gray-500">Loading graph data…</p>
        </div>
      )}

      <div ref={containerRef} className="flex-1 min-h-[500px] border border-gray-200 rounded-lg bg-white">
        <svg ref={svgRef} className="w-full h-full" />
      </div>
    </div>
  )
}
