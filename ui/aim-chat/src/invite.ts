const ASCII_WHITESPACE = /[\t\n\v\f\r ]+/g

function compactInviteToken(value: string): string {
  return value.replace(ASCII_WHITESPACE, '')
}

/** Extract and normalize a raw token from a pasted invite link or bare token. */
export function extractInviteToken(input: string): string {
  const compact = compactInviteToken(input)
  try {
    const url = new URL(compact)
    const invite = url.searchParams.get('invite')
    if (invite) return compactInviteToken(invite)
    if (url.hash) return compactInviteToken(url.hash.replace(/^#/, ''))
  } catch {
    // Not a URL — treat as a bare token.
  }
  return compact
}
