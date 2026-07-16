import type { MachineTag } from '../types/api'

export function groupTagsByNamespace(tags: MachineTag[]): Record<string, MachineTag[]> {
  const groups: Record<string, MachineTag[]> = {}
  for (const tag of tags) {
    if (!groups[tag.namespace]) groups[tag.namespace] = []
    groups[tag.namespace].push(tag)
  }
  return groups
}
