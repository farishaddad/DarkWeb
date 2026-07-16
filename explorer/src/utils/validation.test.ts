import { describe, it, expect } from 'vitest'
import {
  validateSeverity,
  validateConfidence,
  validateTimestamp,
  validateAlertId,
  validatePagination,
} from './validation'

describe('validateSeverity', () => {
  it('accepts "low" as valid', () => {
    expect(validateSeverity('low')).toBeNull()
  })

  it('accepts "medium" as valid', () => {
    expect(validateSeverity('medium')).toBeNull()
  })

  it('accepts "high" as valid', () => {
    expect(validateSeverity('high')).toBeNull()
  })

  it('accepts "critical" as valid', () => {
    expect(validateSeverity('critical')).toBeNull()
  })

  it('rejects an empty string', () => {
    const result = validateSeverity('')
    expect(result).not.toBeNull()
    expect(result).toContain('Invalid severity')
  })

  it('rejects an invalid severity value', () => {
    const result = validateSeverity('extreme')
    expect(result).not.toBeNull()
    expect(result).toContain('Invalid severity')
  })

  it('rejects uppercase variant', () => {
    const result = validateSeverity('High')
    expect(result).not.toBeNull()
    expect(result).toContain('Invalid severity')
  })
})

describe('validateConfidence', () => {
  it('accepts 0.0 as valid', () => {
    expect(validateConfidence(0.0)).toBeNull()
  })

  it('accepts 1.0 as valid', () => {
    expect(validateConfidence(1.0)).toBeNull()
  })

  it('accepts 0.5 as valid', () => {
    expect(validateConfidence(0.5)).toBeNull()
  })

  it('rejects negative values', () => {
    const result = validateConfidence(-0.1)
    expect(result).not.toBeNull()
    expect(result).toContain('out of range')
  })

  it('rejects values greater than 1.0', () => {
    const result = validateConfidence(1.1)
    expect(result).not.toBeNull()
    expect(result).toContain('out of range')
  })

  it('rejects NaN', () => {
    const result = validateConfidence(NaN)
    expect(result).not.toBeNull()
    expect(result).toContain('finite number')
  })

  it('rejects Infinity', () => {
    const result = validateConfidence(Infinity)
    expect(result).not.toBeNull()
    expect(result).toContain('finite number')
  })
})

describe('validateTimestamp', () => {
  it('accepts a valid ISO 8601 timestamp', () => {
    expect(validateTimestamp('2025-01-15T10:30:00Z')).toBeNull()
  })

  it('accepts a date-only ISO string', () => {
    expect(validateTimestamp('2025-01-15')).toBeNull()
  })

  it('accepts a timestamp with timezone offset', () => {
    expect(validateTimestamp('2025-06-01T14:00:00+01:00')).toBeNull()
  })

  it('rejects an empty string', () => {
    const result = validateTimestamp('')
    expect(result).not.toBeNull()
    expect(result).toContain('non-empty')
  })

  it('rejects a whitespace-only string', () => {
    const result = validateTimestamp('   ')
    expect(result).not.toBeNull()
    expect(result).toContain('non-empty')
  })

  it('rejects an invalid timestamp', () => {
    const result = validateTimestamp('not-a-date')
    expect(result).not.toBeNull()
    expect(result).toContain('Invalid timestamp')
  })
})

describe('validateAlertId', () => {
  it('accepts a non-empty string', () => {
    expect(validateAlertId('alert-001')).toBeNull()
  })

  it('accepts a UUID-like string', () => {
    expect(validateAlertId('550e8400-e29b-41d4-a716-446655440000')).toBeNull()
  })

  it('rejects an empty string', () => {
    const result = validateAlertId('')
    expect(result).not.toBeNull()
    expect(result).toContain('non-empty')
  })

  it('rejects a whitespace-only string', () => {
    const result = validateAlertId('   ')
    expect(result).not.toBeNull()
    expect(result).toContain('non-empty')
  })
})

describe('validatePagination', () => {
  it('accepts page=1, pageSize=10', () => {
    expect(validatePagination(1, 10)).toBeNull()
  })

  it('accepts page=5, pageSize=50', () => {
    expect(validatePagination(5, 50)).toBeNull()
  })

  it('accepts page=1, pageSize=100', () => {
    expect(validatePagination(1, 100)).toBeNull()
  })

  it('rejects page=0', () => {
    const result = validatePagination(0, 20)
    expect(result).not.toBeNull()
    expect(result).toContain('greater than or equal to 1')
  })

  it('rejects negative page', () => {
    const result = validatePagination(-1, 20)
    expect(result).not.toBeNull()
    expect(result).toContain('greater than or equal to 1')
  })

  it('rejects pageSize below 10', () => {
    const result = validatePagination(1, 5)
    expect(result).not.toBeNull()
    expect(result).toContain('between 10 and 100')
  })

  it('rejects pageSize above 100', () => {
    const result = validatePagination(1, 101)
    expect(result).not.toBeNull()
    expect(result).toContain('between 10 and 100')
  })

  it('rejects non-integer page', () => {
    const result = validatePagination(1.5, 20)
    expect(result).not.toBeNull()
    expect(result).toContain('integer')
  })

  it('rejects non-integer pageSize', () => {
    const result = validatePagination(1, 20.5)
    expect(result).not.toBeNull()
    expect(result).toContain('integer')
  })
})
