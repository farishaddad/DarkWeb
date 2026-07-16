export function redactUrl(url: string): string {
  try {
    const parsed = new URL(url)
    return parsed.hostname
  } catch {
    // If URL parsing fails, return the domain-like portion
    const match = url.match(/^(?:https?:\/\/)?([^\/\?#]+)/)
    return match ? match[1] : url
  }
}
