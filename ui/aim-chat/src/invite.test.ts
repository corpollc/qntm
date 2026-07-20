import { describe, expect, it } from 'vitest'
import { extractInviteToken } from './invite'

describe('extractInviteToken', () => {
  it('removes embedded ASCII whitespace from bare tokens', () => {
    expect(extractInviteToken('  abc\n def\tghi\r\n  ')).toBe('abcdefghi')
  })

  it('normalizes wrapped tokens in invite links', () => {
    expect(extractInviteToken('https://chat.corpo.llc/?invite=abc%0Adef%09ghi')).toBe('abcdefghi')
  })

  it('normalizes fragment-style invite links', () => {
    expect(extractInviteToken('https://chat.corpo.llc/#abc def\nghi')).toBe('abcdefghi')
  })
})
