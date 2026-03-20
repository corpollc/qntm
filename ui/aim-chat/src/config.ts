export const HOSTED_GATEWAY_URL = 'https://gateway.qntm.corpo.llc'
export const LEGACY_LOCAL_GATEWAY_URL = 'http://localhost:8080'

export function getDefaultGatewayUrl(): string {
  const configured = import.meta.env.VITE_DEFAULT_GATEWAY_URL?.trim()
  if (configured) {
    return configured
  }

  if (typeof window !== 'undefined') {
    const host = window.location.hostname
    if (host === 'web.qntm.corpo.llc' || host.endsWith('.pages.dev')) {
      return HOSTED_GATEWAY_URL
    }
  }

  return LEGACY_LOCAL_GATEWAY_URL
}
