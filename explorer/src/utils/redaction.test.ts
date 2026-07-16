import { describe, it, expect } from 'vitest'
import { redactUrl } from './redaction'

describe('redactUrl', () => {
  it('extracts hostname from a valid http URL', () => {
    expect(redactUrl('http://example.onion/path/to/page')).toBe('example.onion')
  })

  it('extracts hostname from a valid https URL', () => {
    expect(redactUrl('https://dark-market.onion/forum/thread?id=123')).toBe('dark-market.onion')
  })

  it('removes query string and fragment from URL', () => {
    expect(redactUrl('https://forum.onion/page?q=secret#anchor')).toBe('forum.onion')
  })

  it('handles URL with port number', () => {
    expect(redactUrl('http://hidden-service.onion:8080/api/data')).toBe('hidden-service.onion')
  })

  it('handles non-standard URL by extracting domain portion', () => {
    expect(redactUrl('some-domain.onion/path')).toBe('some-domain.onion')
  })

  it('handles URL with only a domain (no path)', () => {
    expect(redactUrl('https://example.onion')).toBe('example.onion')
  })

  it('returns original string when no domain can be extracted', () => {
    expect(redactUrl('')).toBe('')
  })
})
