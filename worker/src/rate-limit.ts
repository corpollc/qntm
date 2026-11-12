/** Best-effort, per-isolate protection; this is not a global quota. */
export const MAX_RATE_LIMIT_IPS = 10_000;
export const RATE_LIMIT_WINDOW_MS = 60_000;
const MAX_IP_LENGTH = 64;

function parseIPv4Octets(input: string): [number, number, number, number] | null {
	const parts = input.split(".");
	if (parts.length !== 4) return null;
	const octets: number[] = [];
	for (const part of parts) {
		if (!/^(?:0|[1-9]\d{0,2})$/.test(part)) return null;
		const n = Number(part);
		if (n < 0 || n > 255) return null;
		octets.push(n);
	}
	return octets as [number, number, number, number];
}

function parseIPv6Hextets(input: string): number[] | null {
	if (!input.includes(":")) return null;
	let addr = input.trim();
	if (addr.startsWith("[")) {
		const closeBracket = addr.indexOf("]");
		if (closeBracket === -1) return null;
		const rest = addr.slice(closeBracket + 1);
		if (rest !== "" && !rest.startsWith("%")) return null;
		addr = addr.slice(1, closeBracket) + rest;
	}
	const zoneIdx = addr.indexOf("%");
	if (zoneIdx !== -1) {
		if (zoneIdx === 0 || zoneIdx === addr.length - 1) return null;
		addr = addr.slice(0, zoneIdx);
	}
	const doubleColonParts = addr.split("::");
	if (doubleColonParts.length > 2) return null;

	const parseSide = (side: string, allowIPv4Tail: boolean): number[] | null => {
		if (side === "") return [];
		const tokens = side.split(":");
		const out: number[] = [];
		for (let i = 0; i < tokens.length; i++) {
			const token = tokens[i];
			if (allowIPv4Tail && i === tokens.length - 1 && token.includes(".")) {
				const octets = parseIPv4Octets(token);
				if (!octets) return null;
				out.push((octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]);
			} else {
				if (!/^[0-9a-fA-F]{1,4}$/.test(token)) return null;
				out.push(parseInt(token, 16));
			}
		}
		return out;
	};

	if (doubleColonParts.length === 1) {
		const hextets = parseSide(doubleColonParts[0], true);
		return hextets && hextets.length === 8 ? hextets : null;
	}

	const left = parseSide(doubleColonParts[0], false);
	const right = parseSide(doubleColonParts[1], true);
	if (!left || !right) return null;
	const missing = 8 - (left.length + right.length);
	if (missing < 1) return null;
	return [...left, ...new Array<number>(missing).fill(0), ...right];
}

/**
 * Normalize client IP strings for rate-limiting:
 * - IPv4 and IPv4-mapped IPv6 (::ffff:a.b.c.d) -> canonical a.b.c.d
 * - Native IPv6 -> canonical /64 prefix (xxxx:xxxx:xxxx:xxxx::/64) so a single /64
 *   allocation cannot mint thousands of distinct keys.
 * - Other bounded tokens (e.g. "unknown" or test identifiers) -> preserved as-is.
 */
export function normalizeRateLimitClientKey(ip: string): string | null {
	if (!ip || ip.length > MAX_IP_LENGTH) return null;
	const v4 = parseIPv4Octets(ip);
	if (v4) return `${v4[0]}.${v4[1]}.${v4[2]}.${v4[3]}`;
	const v6 = parseIPv6Hextets(ip);
	if (v6) {
		if (v6[0] === 0 && v6[1] === 0 && v6[2] === 0 && v6[3] === 0 && v6[4] === 0 && v6[5] === 0xffff) {
			return `${v6[6] >> 8}.${v6[6] & 0xff}.${v6[7] >> 8}.${v6[7] & 0xff}`;
		}
		return `${v6[0].toString(16).padStart(4, "0")}:${v6[1].toString(16).padStart(4, "0")}:${v6[2].toString(16).padStart(4, "0")}:${v6[3].toString(16).padStart(4, "0")}::/64`;
	}
	return ip;
}

export class RelayRateLimiter {
	private readonly entries = new Map<string, { count: number; resetAt: number }>();
	private lastNow = 0;
	constructor(
		private readonly clock: () => number = Date.now,
		private readonly maxTrackedClients: number = MAX_RATE_LIMIT_IPS,
	) {}

	get size(): number { return this.entries.size; }

	check(ip: string, maxPerMinute: number): boolean {
		// Clamp backward clock adjustments so insertion order remains expiry order.
		const now = this.lastNow = Math.max(this.lastNow, this.clock());
		for (const [key, entry] of this.entries) {
			if (entry.resetAt > now) break;
			this.entries.delete(key);
		}
		const normalizedKey = normalizeRateLimitClientKey(ip);
		if (!normalizedKey || !Number.isSafeInteger(maxPerMinute) || maxPerMinute < 1) return false;
		const entry = this.entries.get(normalizedKey);
		if (entry) {
			if (entry.count >= maxPerMinute) return false;
			entry.count++;
			return true;
		}
		// When at capacity after purging expired entries, evict the oldest non-exhausted
		// bucket first (preserving active rate-limit blocks against churn), falling back
		// to the oldest FIFO bucket so new clients are never globally locked out.
		if (this.entries.size >= this.maxTrackedClients) {
			let evictKey: string | undefined;
			for (const [candidateKey, candidateEntry] of this.entries) {
				if (candidateEntry.count < maxPerMinute) {
					evictKey = candidateKey;
					break;
				}
			}
			if (evictKey === undefined) {
				evictKey = this.entries.keys().next().value;
			}
			if (evictKey !== undefined) {
				this.entries.delete(evictKey);
			}
		}
		this.entries.set(normalizedKey, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
		return true;
	}
}
