import { defineProject } from "vitest/config";

export default defineProject({
	resolve: {
		conditions: ["dev-source"],
	},
});
