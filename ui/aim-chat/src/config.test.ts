import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  formatRecipeUrls,
  getDefaultGatewayUrl,
  getServiceHeaderDefaults,
  HOSTED_GATEWAY_URL,
  LEGACY_LOCAL_GATEWAY_URL,
  resolveServiceOrigins,
} from './config'

describe('config security and wire contracts', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('defaults chat.corpo.llc, web.qntm.corpo.llc, and pages.dev to the hosted gateway URL', () => {
    for (const hostname of ['chat.corpo.llc', 'web.qntm.corpo.llc', 'preview.aim-chat.pages.dev']) {
      vi.stubGlobal('window', { location: { hostname } })
      expect(getDefaultGatewayUrl()).toBe(HOSTED_GATEWAY_URL)
    }

    vi.stubGlobal('window', { location: { hostname: 'localhost' } })
    expect(getDefaultGatewayUrl()).toBe(LEGACY_LOCAL_GATEWAY_URL)
  })

  it('excludes localhost and 127.0.0.1 from production CSP connect-src in public/_headers', () => {
    const headersFile = readFileSync(resolve(import.meta.dirname, '../public/_headers'), 'utf8')
    expect(headersFile).toContain('connect-src')
    expect(headersFile).not.toContain('localhost')
    expect(headersFile).not.toContain('127.0.0.1')
  })

  it('resolves built-in service names, HTTPS hostnames, and loopback HTTP origins while rejecting unsafe inputs', () => {
    expect(resolveServiceOrigins('github')).toEqual(['https://api.github.com'])
    expect(resolveServiceOrigins('OPENAI')).toEqual(['https://api.openai.com'])
    expect(resolveServiceOrigins('anthropic')).toEqual(['https://api.anthropic.com'])
    expect(resolveServiceOrigins('gemini')).toEqual(['https://generativelanguage.googleapis.com'])
    expect(resolveServiceOrigins('stripe')).toEqual(['https://api.stripe.com'])
    expect(resolveServiceOrigins('fun')).toEqual(['http://localhost:9090'])
    expect(resolveServiceOrigins('api.example.com')).toEqual(['https://api.example.com'])
    expect(resolveServiceOrigins('https://api.example.com:8443')).toEqual(['https://api.example.com:8443'])
    expect(resolveServiceOrigins('localhost:8080')).toEqual(['http://localhost:8080'])
    expect(resolveServiceOrigins('127.0.0.1:9000')).toEqual(['http://127.0.0.1:9000'])

    expect(resolveServiceOrigins('')).toBeNull()
    expect(resolveServiceOrigins('demo')).toBeNull()
    expect(resolveServiceOrigins('http://api.example.com')).toBeNull()
    expect(resolveServiceOrigins('https://api.example.com/v1')).toBeNull()
    expect(resolveServiceOrigins('https://api.example.com?token=1')).toBeNull()
    expect(resolveServiceOrigins('https://user:pass@api.example.com')).toBeNull()

    expect(getServiceHeaderDefaults('anthropic')).toEqual({ headerName: 'x-api-key', headerTemplate: '{value}' })
    expect(getServiceHeaderDefaults('gemini')).toEqual({ headerName: 'x-goog-api-key', headerTemplate: '{value}' })
    expect(getServiceHeaderDefaults('openai')).toEqual({ headerName: 'Authorization', headerTemplate: 'Bearer {value}' })
  })

  it('URL-encodes recipe path and query parameters and rejects dot-segment traversal', () => {
    const recipe = {
      endpoint: '/repos/{owner}/{repo}',
      target_url: 'https://api.github.com/repos/{owner}/{repo}',
      path_params: [
        { name: 'owner', type: 'string', description: 'Owner', required: true },
        { name: 'repo', type: 'string', description: 'Repo', required: true },
      ],
      query_params: [{ name: 'q', type: 'string', description: 'Filter', required: false }],
    }

    const formatted = formatRecipeUrls(recipe, {
      owner: 'acme/evil',
      repo: 'app?admin=true#frag',
      q: 'a&b=1',
    })
    expect(formatted.endpoint).toBe('/repos/acme%2Fevil/app%3Fadmin%3Dtrue%23frag')
    expect(formatted.target_url).toBe(
      'https://api.github.com/repos/acme%2Fevil/app%3Fadmin%3Dtrue%23frag?q=a%26b%3D1',
    )

    expect(() => formatRecipeUrls(recipe, { owner: '..', repo: 'app' })).toThrow('dot segments')
    expect(() => formatRecipeUrls(recipe, { owner: '.', repo: 'app' })).toThrow('dot segments')
  })
})
