export interface ReceiptRecord {
	readers: string[];
	receipts: number;
	shouldDelete: false;
}

/**
 * Record a unique reader without granting the reader any retention authority.
 *
 * The relay cannot verify conversation membership from an opaque envelope, so
 * a receipt can be telemetry only. Message retention remains controlled by the
 * server-side TTL.
 */
export function recordReceipt(readers: readonly string[], readerKID: string): ReceiptRecord {
	const nextReaders = readers.includes(readerKID) ? [...readers] : [...readers, readerKID];
	return {
		readers: nextReaders,
		receipts: nextReaders.length,
		shouldDelete: false,
	};
}

export function countRecentConversations(stats: Record<string, number>, cutoff: number): number {
	return Object.values(stats).filter((timestamp) => timestamp >= cutoff).length;
}
