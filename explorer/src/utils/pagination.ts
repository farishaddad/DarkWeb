import type { AlertSummary } from '../types/api'
import type { PaginatedAlerts } from '../types/filters'

/**
 * Paginates an array of alerts based on page number and page size.
 *
 * @param alerts - The full array of alerts to paginate
 * @param page - The page number (must be >= 1)
 * @param pageSize - The number of items per page (must be in [10, 100])
 * @returns A PaginatedAlerts object with the sliced alerts and pagination metadata
 * @throws Error if page < 1 or pageSize is outside [10, 100]
 */
export function paginate(
  alerts: AlertSummary[],
  page: number,
  pageSize: number
): PaginatedAlerts {
  if (page < 1) {
    throw new Error(
      `Invalid page: ${page}. Page must be greater than or equal to 1.`
    )
  }

  if (pageSize < 10 || pageSize > 100) {
    throw new Error(
      `Invalid pageSize: ${pageSize}. Page size must be between 10 and 100.`
    )
  }

  const totalCount = alerts.length
  const startIndex = (page - 1) * pageSize
  const endIndex = startIndex + pageSize
  const sliced = alerts.slice(startIndex, endIndex)
  const hasMore = endIndex < totalCount

  return {
    alerts: sliced,
    totalCount,
    page,
    pageSize,
    hasMore,
  }
}
