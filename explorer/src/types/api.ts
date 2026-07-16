import type {
  AlertType,
  FraudCategory,
  IntelligenceTier,
  Severity,
} from './models'

export interface ApiResponse<T> {
  data: T
  meta: {
    requestId: string
    timestamp: string
    dataSource: 'live' | 'mock'
  }
  error?: {
    code: string
    message: string
  }
}

export interface AlertSummary {
  alertId: string
  alertType: AlertType
  severity: Severity
  category: FraudCategory
  tier: IntelligenceTier
  ttpDescription: string
  affectedInstitutions: string[]
  createdAt: string
  tagCount: number
}

export interface AlertDetail {
  alertId: string
  alertType: AlertType
  severity: Severity
  category: FraudCategory
  tier: IntelligenceTier
  ttpDescription: string
  affectedInstitutions: string[]
  detectionRules: DetectionRule[]
  relatedIntelligence: string[]
  provenance: ProvenanceChain
  tags: MachineTag[]
  galaxyMatch: GalaxyMatch | null
  createdAt: string
}

export interface ProvenanceChain {
  originalSourceUrl: string
  crawlTimestamp: string
  s3ArtifactKey: string
  processingChain: ProcessingStep[]
}

export interface ProcessingStep {
  agentId: string
  agentName: string
  timestamp: string
  inputKey: string
  outputKey: string
  summary: string
}

export interface DetectionRule {
  ruleType: 'yara' | 'sigma' | 'custom'
  ruleContent: string
  confidence: number
}

export interface MachineTag {
  namespace: string
  predicate: string
  value: string
}

export interface GalaxyMatch {
  galaxy: string
  clusterUuid: string
  clusterValue: string
  source: string
}
