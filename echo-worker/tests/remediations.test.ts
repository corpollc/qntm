import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
	createConversation,
	createInvite,
	createMessage,
	decryptMessage,
	deriveConversationKeys,
	deserializeEnvelope,
	generateIdentity,
	serializeEnvelope,
} from "@corpollc/qntm";
import { handleConversation, type Env } from "../src/index.js";

function createFixture() {
	const sender = generateIdentity();
	const bot = generateIdentity();
	const invite = createInvite(sender, "direct");
	const conv = createConversation(invite, deriveConversationKeys(invite));
	const storage = new Map<string, string>();
	const env = {
		RELAY_URL: "http://relay.invalid",
		ECHO_KV: {
			get: async (key: string) => storage.get(key) ?? null,
			put: async (key: string, value: string) => {
				storage.set(key, value);
			},
			delete: async (key: string) => {
				storage.delete(key);
			},
		},
	} as unknown as Env;
	const makeEnvelope = (text: string) =>
		serializeEnvelope(createMessage(sender, conv, "text", new TextEncoder().encode(text)));
	return { sender, bot, conv, storage, env, makeEnvelope };
}

describe("P2-7: echo-worker replay deduplication", () => {
	it("retries persisted reply after a failed postMessage, then ignores replayed msg_id ciphertexts at higher sequences", async () => {
		const f = createFixture();
		const originalCiphertext = f.makeEnvelope("hello echo");
		const freshCiphertext = f.makeEnvelope("second distinct message");

		// Tick 1: postMessage fails before delivery completes
		let cachedReply: Uint8Array | undefined;
		await assert.rejects(
			handleConversation(
				f.env,
				f.bot,
				f.conv,
				{
					postMessage: async (_id, bytes) => {
						cachedReply = bytes;
						throw new Error("transient relay error");
					},
				},
				"",
				async () => ({ messages: [{ seq: 1, envelope: originalCiphertext }], sequence: 1 }),
			),
			/transient relay error/,
		);
		assert.equal(f.storage.get("echo-bot-cursor"), undefined);

		// Tick 2: retry succeeds with the exact cached reply bytes
		const published: Uint8Array[] = [];
		const echoed1 = await handleConversation(
			f.env,
			f.bot,
			f.conv,
			{
				postMessage: async (_id, bytes) => {
					published.push(bytes);
					return 2;
				},
			},
			"",
			async () => ({ messages: [{ seq: 1, envelope: originalCiphertext }], sequence: 1 }),
		);
		assert.equal(echoed1, 1);
		assert.equal(published.length, 1);
		assert.deepEqual(Buffer.from(published[0]), Buffer.from(cachedReply!));
		assert.equal(f.storage.get("echo-bot-cursor"), "1");

		// Tick 3: attacker replays originalCiphertext multiple times (seq 3, 4) alongside a genuine message (seq 5)
		const echoed2 = await handleConversation(
			f.env,
			f.bot,
			f.conv,
			{
				postMessage: async (_id, bytes) => {
					published.push(bytes);
					return 6;
				},
			},
			"",
			async (_url, _id, cursor) => {
				assert.equal(cursor, 1);
				return {
					messages: [
						{ seq: 3, envelope: originalCiphertext },
						{ seq: 4, envelope: originalCiphertext },
						{ seq: 5, envelope: freshCiphertext },
					],
					sequence: 5,
				};
			},
		);

		// Only the genuine fresh message is echoed; replays are skipped and cursor advances to 5
		assert.equal(echoed2, 1);
		assert.equal(published.length, 2);
		assert.equal(f.storage.get("echo-bot-cursor"), "5");
		const secondBody = new TextDecoder().decode(decryptMessage(deserializeEnvelope(published[1]), f.conv).inner.body);
		assert.equal(secondBody, "🔒 echo: second distinct message");
	});
});
