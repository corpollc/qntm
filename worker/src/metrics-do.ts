import { DurableObject } from "cloudflare:workers";
import { RelayMetricsStore, type RelayMetricEvent } from "./metrics.js";
import type { Env } from "./index.js";

/** Internal binding only. Public routing exposes aggregate reads, never ingestion. */
export class RelayMetricsDO extends DurableObject<Env> {
	private metrics: RelayMetricsStore;
	constructor(ctx: DurableObjectState, env: Env) {
		super(ctx, env);
		this.metrics = new RelayMetricsStore(ctx.storage);
		ctx.blockConcurrencyWhile(() => this.metrics.maintain());
	}

	async alarm(): Promise<void> { await this.metrics.maintain(); }

	async fetch(request: Request): Promise<Response> {
		const path = new URL(request.url).pathname;
		if (request.method === "POST" && path === "/record") {
			let events: RelayMetricEvent[];
			try {
				events = await request.json();
				if (!Array.isArray(events)) throw new Error("invalid batch");
				this.metrics.record(events);
			} catch { return new Response("invalid telemetry", { status: 400 }); }
			await this.metrics.maintain();
			return Response.json({ recorded: true });
		}
		if (request.method === "GET" && path === "/snapshot") {
			return Response.json(this.metrics.snapshot(), { headers: { "Cache-Control": "no-store" } });
		}
		return new Response("not found", { status: 404 });
	}
}
