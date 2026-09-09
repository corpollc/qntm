import { describe, it, expect } from 'vitest'
import { buildInviteLink, extractToken } from './utils'
import { createInvite, generateIdentity, inviteFromURL, inviteToToken } from '@corpollc/qntm'
import { parseInviteConvId } from './qntm'

describe('browser invite links', () => {
  it('puts the secret only in a fragment, replaces existing routing and drops outer queries', () => {
    const invite = createInvite(generateIdentity(), 'group')
    const token = inviteToToken(invite)
    const link = buildInviteLink(token, 'https://chat.corpo.llc/?invite=old&tracking=value#/settings')
    const url = new URL(link)
    expect(url.search).toBe('')
    expect(url.hash).toBe(`#${token}`)
    expect(`${url.origin}${url.pathname}${url.search}`).not.toContain(token)
    expect(inviteFromURL(link)).toEqual(invite)
    expect(extractToken(link)).toBe(token)
  })
})

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

  it('normalizes wrapped tokens in fragment links before URL parsing', () => {
    expect(extractToken('https://chat.corpo.llc/#abc def\nghi')).toBe('abcdefghi')
  })

  it('normalizes encoded whitespace in query invite links', () => {
    expect(extractToken('https://chat.corpo.llc/?invite=abc%0Adef%09ghi')).toBe('abcdefghi')
  })

  it('returns empty string for empty input', () => {
    expect(extractToken('')).toBe('')
  })
})

describe('parseInviteConvId', () => {
  it('returns null for garbage input', () => {
    expect(parseInviteConvId('not-a-token')).toBeNull()
  })

  it('returns null for empty string', () => {
    expect(parseInviteConvId('')).toBeNull()
  })
})
