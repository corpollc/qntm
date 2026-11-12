export class GatewayValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GatewayValidationError';
  }
}

export const MAX_ALLOWED_ORIGINS = 16;

export const KNOWN_SERVICE_ORIGINS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  github: Object.freeze(['https://api.github.com']),
  openai: Object.freeze(['https://api.openai.com']),
  anthropic: Object.freeze(['https://api.anthropic.com']),
  gemini: Object.freeze(['https://generativelanguage.googleapis.com']),
  stripe: Object.freeze(['https://api.stripe.com']),
  hackernews: Object.freeze(['https://hacker-news.firebaseio.com']),
  httpbin: Object.freeze(['https://httpbin.org']),
  dadjokes: Object.freeze(['https://icanhazdadjoke.com']),
  trivia: Object.freeze(['https://opentdb.com']),
  dogs: Object.freeze(['https://dog.ceo']),
  fun: Object.freeze(['http://localhost:9090']),
});

const EXPLICIT_LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);
const EXPLICIT_LOOPBACK_AUTHORITY_RE = /^(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/i;
const CLEAN_API_PREFIX_RE = /^(?:\/(?:api|v\d+(?:[._-]?[a-z0-9]+)?))+$/i;

export function isExplicitLoopbackHost(hostname: string): boolean {
  return EXPLICIT_LOOPBACK_HOSTS.has(hostname.toLowerCase());
}

function parseIPv4Octets(hostname: string): [number, number, number, number] | null {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(hostname);
  if (!match) return null;
  const octets = [Number(match[1]), Number(match[2]), Number(match[3]), Number(match[4])] as [number, number, number, number];
  if (octets.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return octets;
}

function isBlockedIPv4Octets([a, b, c]: [number, number, number, number]): boolean {
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 127) return true; // 127.0.0.0/8
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 (link-local & cloud metadata)
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 192 && b === 0 && c === 0) return true; // 192.0.0.0/24
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15
  if (a >= 224) return true; // multicast & reserved (224.0.0.0/4, 240.0.0.0/4)
  return false;
}

function parseIPv6Groups(bracketedHostname: string): number[] | null {
  if (!bracketedHostname.startsWith('[') || !bracketedHostname.endsWith(']')) return null;
  const raw = bracketedHostname.slice(1, -1).toLowerCase();
  if (!raw || raw.includes('%')) return null;
  const doubleColonParts = raw.split('::');
  if (doubleColonParts.length > 2) return null;

  const parseSide = (side: string): number[] | null => {
    if (!side) return [];
    const tokens = side.split(':');
    const groups: number[] = [];
    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];
      if (token.includes('.')) {
        if (i !== tokens.length - 1) return null;
        const v4 = parseIPv4Octets(token);
        if (!v4) return null;
        groups.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
      } else {
        if (!/^[0-9a-f]{1,4}$/.test(token)) return null;
        groups.push(parseInt(token, 16));
      }
    }
    return groups;
  };

  const left = parseSide(doubleColonParts[0]);
  if (!left) return null;
  if (doubleColonParts.length === 1) {
    return left.length === 8 ? left : null;
  }
  const right = parseSide(doubleColonParts[1]);
  if (!right) return null;
  const missing = 8 - (left.length + right.length);
  if (missing < 1) return null;
  return [...left, ...new Array<number>(missing).fill(0), ...right];
}

function isBlockedIPv6Groups(groups: number[]): boolean {
  // Unspecified ::/128
  if (groups.every(g => g === 0)) return true;
  // Loopback ::1/128
  if (groups.slice(0, 7).every(g => g === 0) && groups[7] === 1) return true;
  // IPv4-mapped ::ffff:0:0/96 or IPv4-compatible ::/96
  if (groups.slice(0, 5).every(g => g === 0) && (groups[5] === 0xffff || groups[5] === 0)) {
    const v4: [number, number, number, number] = [
      (groups[6] >> 8) & 0xff,
      groups[6] & 0xff,
      (groups[7] >> 8) & 0xff,
      groups[7] & 0xff,
    ];
    if (isBlockedIPv4Octets(v4)) return true;
  }
  // NAT64 well-known 64:ff9b::/96 and local-use 64:ff9b:1::/48
  if (groups[0] === 0x0064 && groups[1] === 0xff9b &&
      ((groups[2] === 0 && groups[3] === 0 && groups[4] === 0 && groups[5] === 0) || groups[2] === 1)) {
    const v4: [number, number, number, number] = [
      (groups[6] >> 8) & 0xff,
      groups[6] & 0xff,
      (groups[7] >> 8) & 0xff,
      groups[7] & 0xff,
    ];
    if (isBlockedIPv4Octets(v4)) return true;
  }
  // Discard-only 100::/64
  if (groups[0] === 0x0100 && groups[1] === 0 && groups[2] === 0 && groups[3] === 0) return true;
  // Unique local fc00::/7
  if ((groups[0] & 0xfe00) === 0xfc00) return true;
  // Link-local fe80::/10
  if ((groups[0] & 0xffc0) === 0xfe80) return true;
  // Multicast ff00::/8
  if ((groups[0] & 0xff00) === 0xff00) return true;
  return false;
}

export function isBlockedOrPrivateHost(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/\.$/, '');
  if (!normalized) return true;
  if (normalized === 'localhost' || normalized.endsWith('.localhost') ||
      normalized === 'metadata.google.internal' || normalized.endsWith('.internal')) {
    return true;
  }
  if (/^(?:0x[0-9a-f]+|\d+)$/i.test(normalized)) return true;
  if (hostname.startsWith('[')) {
    const groups = parseIPv6Groups(hostname);
    if (!groups) return true;
    return isBlockedIPv6Groups(groups);
  }
  const v4 = parseIPv4Octets(normalized);
  if (v4) return isBlockedIPv4Octets(v4);
  if (!normalized.includes('.')) return true;
  return false;
}

function extractRawAuthorityAndPath(raw: string): { authority: string; path: string } {
  const qIndex = raw.indexOf('?');
  const hIndex = raw.indexOf('#');
  const cut = qIndex === -1 ? hIndex : hIndex === -1 ? qIndex : Math.min(qIndex, hIndex);
  const beforeQuery = cut === -1 ? raw : raw.slice(0, cut);
  const match = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/]*)(.*)$/.exec(beforeQuery);
  if (!match) throw new GatewayValidationError('Invalid URL');
  return { authority: match[2], path: match[3] || '/' };
}

function assertNoDotSegments(pathText: string, label: string): void {
  if (!pathText.startsWith('/') || pathText.includes('\\')) {
    throw new GatewayValidationError(`Invalid ${label}`);
  }
  const segments = pathText.split('/');
  for (let i = 1; i < segments.length; i++) {
    const seg = segments[i];
    if (seg === '.' || seg === '..') {
      throw new GatewayValidationError(`Invalid ${label}: dot-segment path traversal is not allowed`);
    }
    let decoded: string;
    try {
      decoded = decodeURIComponent(seg);
    } catch {
      throw new GatewayValidationError(`Invalid ${label}: malformed percent-encoding`);
    }
    if (/[\u0000-\u001f\u007f\\]/.test(decoded)) {
      throw new GatewayValidationError(`Invalid ${label}`);
    }
    for (const sub of decoded.split('/')) {
      if (sub === '.' || sub === '..') {
        throw new GatewayValidationError(`Invalid ${label}: dot-segment path traversal is not allowed`);
      }
    }
  }
}

export function normalizeAllowedOrigin(raw: string): string {
  if (typeof raw !== 'string' || !raw || raw.length > 2048 || raw.trim() !== raw || /[?#\\]/.test(raw)) {
    throw new GatewayValidationError('Invalid allowed origin');
  }
  const { authority, path } = extractRawAuthorityAndPath(raw);
  if (path !== '/' && path !== '') {
    throw new GatewayValidationError('Allowed origin must not include a path');
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new GatewayValidationError('Invalid allowed origin');
  }
  if (url.username || url.password || (url.pathname !== '/' && url.pathname !== '') ||
      url.search || url.hash || url.origin === 'null') {
    throw new GatewayValidationError('Invalid allowed origin');
  }
  if (url.protocol === 'http:') {
    if (!isExplicitLoopbackHost(url.hostname) || !EXPLICIT_LOOPBACK_AUTHORITY_RE.test(authority)) {
      throw new GatewayValidationError('HTTP allowed_origins are restricted to localhost, 127.0.0.1, or [::1]');
    }
    return url.origin;
  }
  if (url.protocol === 'https:') {
    if (isBlockedOrPrivateHost(url.hostname)) {
      throw new GatewayValidationError('HTTPS allowed_origins cannot target private, loopback, or metadata hosts');
    }
    return url.origin;
  }
  throw new GatewayValidationError('Allowed origin must use https:// (or http:// on localhost)');
}

export function normalizeAllowedOriginsList(origins: unknown): string[] {
  if (!Array.isArray(origins) || origins.length < 1 || origins.length > MAX_ALLOWED_ORIGINS) {
    throw new GatewayValidationError(`allowed_origins must be an array of 1 to ${MAX_ALLOWED_ORIGINS} origins`);
  }
  const result: string[] = [];
  const seen = new Set<string>();
  for (const item of origins) {
    if (typeof item !== 'string') {
      throw new GatewayValidationError('Invalid allowed origin');
    }
    const normalized = normalizeAllowedOrigin(item);
    if (!seen.has(normalized)) {
      seen.add(normalized);
      result.push(normalized);
    }
  }
  if (result.length < 1 || result.length > MAX_ALLOWED_ORIGINS) {
    throw new GatewayValidationError(`allowed_origins must contain 1 to ${MAX_ALLOWED_ORIGINS} origins`);
  }
  return result;
}

export function resolveServiceOrigins(service: string, explicitOrigins?: readonly string[]): string[] {
  if (typeof service !== 'string' || !service.trim()) {
    throw new GatewayValidationError('Invalid service');
  }
  if (explicitOrigins !== undefined && explicitOrigins.length > 0) {
    return normalizeAllowedOriginsList(explicitOrigins);
  }
  const trimmed = service.trim();
  if (/^https?:\/\//i.test(trimmed)) {
    return [normalizeAllowedOrigin(trimmed)];
  }
  const lower = trimmed.toLowerCase();
  if (Object.prototype.hasOwnProperty.call(KNOWN_SERVICE_ORIGINS, lower)) {
    return [...KNOWN_SERVICE_ORIGINS[lower]];
  }
  if (EXPLICIT_LOOPBACK_AUTHORITY_RE.test(trimmed)) {
    return [normalizeAllowedOrigin(`http://${trimmed}`)];
  }
  if (trimmed.includes('.')) {
    return [normalizeAllowedOrigin(`https://${trimmed}`)];
  }
  throw new GatewayValidationError(
    `Unknown service "${service}": specify an API hostname (e.g. api.example.com) or pass allowedOrigins`,
  );
}

export function validateGatewayTargetUrl(rawUrl: string): URL {
  if (typeof rawUrl !== 'string' || !rawUrl || rawUrl.length > 16384 || rawUrl.trim() !== rawUrl) {
    throw new GatewayValidationError('Invalid target URL');
  }
  if (rawUrl.includes('#') || /[\u0000-\u001f\u007f]/.test(rawUrl)) {
    throw new GatewayValidationError('Invalid target URL');
  }
  const { authority, path: rawPath } = extractRawAuthorityAndPath(rawUrl);
  assertNoDotSegments(rawPath, 'target URL');

  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new GatewayValidationError('Invalid target URL');
  }
  if (url.username || url.password || url.hash || url.origin === 'null') {
    throw new GatewayValidationError('Invalid target URL');
  }
  assertNoDotSegments(url.pathname, 'target URL');

  if (url.protocol === 'http:') {
    if (!isExplicitLoopbackHost(url.hostname) || !EXPLICIT_LOOPBACK_AUTHORITY_RE.test(authority)) {
      throw new GatewayValidationError('HTTP target URLs are restricted to localhost, 127.0.0.1, or [::1]');
    }
    return url;
  }
  if (url.protocol === 'https:') {
    if (isBlockedOrPrivateHost(url.hostname)) {
      throw new GatewayValidationError('Target URL cannot reference private, loopback, link-local, or metadata hosts');
    }
    return url;
  }
  throw new GatewayValidationError('Invalid target URL');
}

export function pathnameMatchesEndpoint(pathname: string, endpoint: string): boolean {
  if (typeof pathname !== 'string' || typeof endpoint !== 'string' ||
      !endpoint.startsWith('/') || /[?#\\\u0000-\u0020\u007f]/.test(endpoint)) {
    return false;
  }
  try {
    assertNoDotSegments(pathname, 'pathname');
    assertNoDotSegments(endpoint, 'endpoint');
  } catch {
    return false;
  }
  if (pathname === endpoint) return true;
  if (endpoint === '/' || !pathname.endsWith(endpoint)) return false;
  const prefix = pathname.slice(0, pathname.length - endpoint.length);
  return CLEAN_API_PREFIX_RE.test(prefix);
}
