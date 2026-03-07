import { defineConfig } from "tsdown";

export default defineConfig({
	dts: { build: true, incremental: true },
	format: ["esm"],
	entry: ["./src/index.ts"],
	external: [
		"@better-auth/core",
		"@better-auth/utils",
		"better-auth",
		"better-call",
	],
	treeshake: true,
});
