import { describe, it, expect } from 'vitest'
import { extractToken } from './utils'

describe('extractToken', () => {
  it('returns bare token as-is', () => {
    expect(extractToken('abc123')).toBe('abc123')
  })

  it('trims leading/trailing whitespace', () => {
    expect(extractToken('  abc123  ')).toBe('abc123')
  })

  it('strips internal whitespace (line breaks, spaces)', () => {
    expect(extractToken('abc 123\n456\t789')).toBe('abc123456789')
  })

  it('extracts token from ?invite= URL param', () => {
    expect(extractToken('https://chat.corpo.llc/?invite=TOKEN123')).toBe('TOKEN123')
  })

  it('extracts token from URL and strips whitespace', () => {
    expect(extractToken('https://chat.corpo.llc/?invite=TOK EN\n123')).toBe('TOKEN123')
  })

  it('extracts token from hash fragment', () => {
    expect(extractToken('https://chat.corpo.llc/#TOKEN123')).toBe('TOKEN123')
  })

  it('returns empty string for empty input', () => {
    expect(extractToken('')).toBe('')
  })
})
