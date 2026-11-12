import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as esbuild from "esbuild";

const here = dirname(fileURLToPath(import.meta.url));
const outDir = mkdtempSync(join(tmpdir(), "qntm-worker-unit-"));
const outfile = join(outDir, "remediations.test.mjs");

try {
	await esbuild.build({
		entryPoints: [resolve(here, "remediations.test.ts")],
		bundle: true,
		platform: "node",
		format: "esm",
		target: "node22",
		outfile,
		external: ["node:*"],
		plugins: [
			{
				name: "cloudflare-workers-shim",
				setup(build) {
					build.onResolve({ filter: /^cloudflare:workers$/ }, () => ({
						path: "cloudflare:workers",
						namespace: "cf-shim",
					}));
					build.onLoad({ filter: /.*/, namespace: "cf-shim" }, () => ({
						contents: `export class DurableObject {
							constructor(ctx, env) {
								this.ctx = ctx;
								this.env = env;
							}
						}`,
						loader: "js",
					}));
				},
			},
		],
	});

	const result = spawnSync(process.execPath, ["--test", outfile], { stdio: "inherit" });
	process.exit(result.status ?? 1);
} finally {
	rmSync(outDir, { recursive: true, force: true });
}
