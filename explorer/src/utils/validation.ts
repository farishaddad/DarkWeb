import type { Severity } from '../types/models'

const VALID_SEVERITIES: ReadonlySet<string> = new Set<Severity>([
  'low',
  'medium',
  'high',
  'critical',
])

/**
 * Validates that a severity value is one of: "low", "medium", "high", "critical".
 * Returns an error message on failure, or null if valid.
 */
export function validateSeverity(value: string): string | null {
  if (!VALID_SEVERITIES.has(value)) {
    return `Invalid severity "${value}". Must be one of: low, medium, high, critical.`
  }
  return null
}

/**
 * Validates that a confidence value is in the range [0.0, 1.0].
 * Returns an error message on failure, or null if valid.
 */
export function validateConfidence(value: number): string | null {
  if (!Number.isFinite(value)) {
    return `Invalid confidence value. Must be a finite number in the range [0.0, 1.0].`
  }
  if (value < 0.0 || value > 1.0) {
    return `Confidence value ${value} is out of range. Must be between 0.0 and 1.0 inclusive.`
  }
  return null
}

/**
 * Validates that a timestamp string is a valid ISO 8601 format.
 * Returns an error message on failure, or null if valid.
 */
export function validateTimestamp(value: string): string | null {
  if (!value || value.trim() === '') {
    return `Timestamp must be a non-empty string in ISO 8601 format.`
  }
  const date = new Date(value)
  if (isNaN(date.getTime())) {
    return `Invalid timestamp "${value}". Must be a valid ISO 8601 timestamp.`
  }
  return null
}

/**
 * Validates that an alertId is a non-empty string.
 * Returns an error message on failure, or null if valid.
 */
export function validateAlertId(value: string): string | null {
  if (!value || value.trim() === '') {
    return `Alert ID must be a non-empty string.`
  }
  return null
}

/**
 * Validates pagination parameters: page >= 1, pageSize in [10, 100].
 * Returns an error message on failure, or null if valid.
 */
export function validatePagination(page: number, pageSize: number): string | null {
  if (!Number.isFinite(page) || !Number.isInteger(page)) {
    return `Page must be an integer greater than or equal to 1.`
  }
  if (page < 1) {
    return `Page must be greater than or equal to 1. Received: ${page}.`
  }
  if (!Number.isFinite(pageSize) || !Number.isInteger(pageSize)) {
    return `Page size must be an integer between 10 and 100.`
  }
  if (pageSize < 10 || pageSize > 100) {
    return `Page size must be between 10 and 100 inclusive. Received: ${pageSize}.`
  }
  return null
}
