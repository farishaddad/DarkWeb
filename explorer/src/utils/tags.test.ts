import { describe, it, expect } from 'vitest'
import { groupTagsByNamespace } from './tags'
import type { MachineTag } from '../types/api'

describe('groupTagsByNamespace', () => {
  it('groups tags by their namespace', () => {
    const tags: MachineTag[] = [
      { namespace: 'mitre-attack', predicate: 'technique', value: 'T1531' },
      { namespace: 'mitre-attack', predicate: 'technique', value: 'T1078' },
      { namespace: 'fraud', predicate: 'category', value: 'account_takeover' },
      { namespace: 'dark-web', predicate: 'source', value: 'forum' },
    ]

    const result = groupTagsByNamespace(tags)

    expect(Object.keys(result)).toHaveLength(3)
    expect(result['mitre-attack']).toHaveLength(2)
    expect(result['fraud']).toHaveLength(1)
    expect(result['dark-web']).toHaveLength(1)
  })

  it('returns empty object for empty tag array', () => {
    const result = groupTagsByNamespace([])
    expect(result).toEqual({})
  })

  it('places all tags in a single group when all share the same namespace', () => {
    const tags: MachineTag[] = [
      { namespace: 'mitre-attack', predicate: 'technique', value: 'T1531' },
      { namespace: 'mitre-attack', predicate: 'tactic', value: 'TA0040' },
      { namespace: 'mitre-attack', predicate: 'technique', value: 'T1078' },
    ]

    const result = groupTagsByNamespace(tags)

    expect(Object.keys(result)).toHaveLength(1)
    expect(result['mitre-attack']).toHaveLength(3)
  })

  it('preserves tag objects in their groups', () => {
    const tag: MachineTag = { namespace: 'fraud', predicate: 'category', value: 'phishing_kit' }
    const result = groupTagsByNamespace([tag])

    expect(result['fraud'][0]).toBe(tag)
  })

  it('creates separate groups for each distinct namespace', () => {
    const tags: MachineTag[] = [
      { namespace: 'ns1', predicate: 'p1', value: 'v1' },
      { namespace: 'ns2', predicate: 'p2', value: 'v2' },
      { namespace: 'ns3', predicate: 'p3', value: 'v3' },
    ]

    const result = groupTagsByNamespace(tags)

    expect(Object.keys(result)).toHaveLength(3)
    expect(result['ns1']).toHaveLength(1)
    expect(result['ns2']).toHaveLength(1)
    expect(result['ns3']).toHaveLength(1)
  })
})
