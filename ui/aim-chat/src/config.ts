import type { GateRecipe } from './types'

export const HOSTED_GATEWAY_URL = 'https://gateway.corpo.llc'
export const LEGACY_LOCAL_GATEWAY_URL = 'http://localhost:8080'

export const BUILTIN_SERVICE_ORIGINS: Record<string, string> = {
  github: 'https://api.github.com',
  openai: 'https://api.openai.com',
  anthropic: 'https://api.anthropic.com',
  gemini: 'https://generativelanguage.googleapis.com',
  stripe: 'https://api.stripe.com',
  hackernews: 'https://hacker-news.firebaseio.com',
  httpbin: 'https://httpbin.org',
  dadjokes: 'https://icanhazdadjoke.com',
  trivia: 'https://opentdb.com',
  dogs: 'https://dog.ceo',
  fun: 'http://localhost:9090',
}

export function getServiceHeaderDefaults(serviceInput: string): { headerName: string; headerTemplate: string } {
  const lower = serviceInput.trim().toLowerCase()
  if (lower === 'anthropic') {
    return { headerName: 'x-api-key', headerTemplate: '{value}' }
  }
  if (lower === 'gemini') {
    return { headerName: 'x-goog-api-key', headerTemplate: '{value}' }
  }
  return { headerName: 'Authorization', headerTemplate: 'Bearer {value}' }
}

export function resolveServiceOrigins(serviceInput: string): string[] | null {
  const raw = serviceInput.trim()
  if (!raw) return null
  const lower = raw.toLowerCase()
  if (Object.prototype.hasOwnProperty.call(BUILTIN_SERVICE_ORIGINS, lower)) {
    return [BUILTIN_SERVICE_ORIGINS[lower]]
  }
  const hasScheme = /^https?:\/\//i.test(raw)
  const isBareLoopback = /^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/i.test(raw)
  if (!hasScheme && !isBareLoopback && !raw.includes('.')) {
    return null
  }
  if (raw.includes('?') || raw.includes('#') || raw.includes('@')) {
    return null
  }
  const candidate = hasScheme ? raw : `${isBareLoopback ? 'http' : 'https'}://${raw}`
  let parsed: URL
  try {
    parsed = new URL(candidate)
  } catch {
    return null
  }
  const loopback = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1' || parsed.hostname === '[::1]'
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopback)) {
    return null
  }
  if (!loopback && !/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(parsed.hostname)) {
    return null
  }
  if (parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) {
    return null
  }
  return [parsed.origin]
}

const PLACEHOLDER_RE = /\{([^}]+)\}/g

function isDotSegment(value: string): boolean {
  const trimmed = value.trim()
  return value === '.' || value === '..' || trimmed === '.' || trimmed === '..'
}

export function formatRecipeUrls(
  recipe: Pick<GateRecipe, 'endpoint' | 'target_url' | 'path_params' | 'query_params'>,
  args: Record<string, string> = {},
  options: { allowUnfilled?: boolean } = {},
): { endpoint: string; target_url: string } {
  const effective: Record<string, string> = { ...args }
  for (const param of recipe.path_params || []) {
    if (!(param.name in effective) || effective[param.name] === '') {
      if (param.default) {
        effective[param.name] = param.default
      } else if (param.required && !options.allowUnfilled) {
        throw new Error(`missing required path parameter "${param.name}"`)
      }
    }
  }
  for (const param of recipe.query_params || []) {
    if (!(param.name in effective) || effective[param.name] === '') {
      if (param.default) {
        effective[param.name] = param.default
      } else if (param.required && !options.allowUnfilled) {
        throw new Error(`missing required query parameter "${param.name}"`)
      }
    }
  }

  const substitute = (template: string): string =>
    template.replace(PLACEHOLDER_RE, (match, key: string) => {
      const val = effective[key]
      if (val === undefined || val === '') {
        return match
      }
      if (isDotSegment(val)) {
        throw new Error(`invalid path parameter "${key}": dot segments are not allowed`)
      }
      return encodeURIComponent(val)
    })

  const endpoint = substitute(recipe.endpoint)
  let targetUrl = substitute(recipe.target_url)

  const queryParts: string[] = []
  for (const param of recipe.query_params || []) {
    const val = effective[param.name] ?? ''
    if (val !== '') {
      queryParts.push(`${encodeURIComponent(param.name)}=${encodeURIComponent(val)}`)
    }
  }
  if (queryParts.length > 0) {
    targetUrl += (targetUrl.includes('?') ? '&' : '?') + queryParts.join('&')
  }

  return { endpoint, target_url: targetUrl }
}

export function getDefaultGatewayUrl(): string {
  const configured = import.meta.env.VITE_DEFAULT_GATEWAY_URL?.trim()
  if (configured) {
    return configured
  }

  if (typeof window !== 'undefined') {
    const host = window.location.hostname
    if (host === 'chat.corpo.llc' || host === 'web.qntm.corpo.llc' || host.endsWith('.pages.dev')) {
      return HOSTED_GATEWAY_URL
    }
  }

  return LEGACY_LOCAL_GATEWAY_URL
}
