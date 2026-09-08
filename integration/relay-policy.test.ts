import { describe, expect, it } from "vitest";
import { countRecentConversations, recordReceipt, MAX_RECEIPT_READERS } from "../worker/src/security-policy.js";

describe("relay security policy", () => {
	it("never grants receipt authors authority to delete a message", () => {
		const first = recordReceipt([], "reader-a");
		const second = recordReceipt(first.readers, "reader-b");

		expect(first).toMatchObject({ receipts: 1, shouldDelete: false });
		expect(second).toMatchObject({ receipts: 2, shouldDelete: false });
	});

	it("deduplicates repeated receipts from the same key", () => {
		const result = recordReceipt(["reader-a"], "reader-a");

		expect(result.readers).toEqual(["reader-a"]);
		expect(result.receipts).toBe(1);
	});

	it("bounds unauthenticated reader telemetry", () => {
		const readers = Array.from({ length: MAX_RECEIPT_READERS }, (_, i) => `reader-${i}`);
		expect(recordReceipt(readers, "one-more").readers).toEqual(readers);
		expect(recordReceipt([...readers, "legacy-overflow"], "new-reader").receipts).toBe(MAX_RECEIPT_READERS);
	});

	it("reports only a recent conversation count", () => {
		const stats = { secretConversationA: 100, secretConversationB: 200 };

		expect(countRecentConversations(stats, 150)).toBe(1);
	});
});
