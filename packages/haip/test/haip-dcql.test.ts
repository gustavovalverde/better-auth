import { describe, expect, it } from "vitest";
import type { DcqlMatcherPresentation } from "../src";
import { createDcqlMatcher } from "../src";

const match = createDcqlMatcher();

function presentation(
	claims: Record<string, unknown>,
	credentialQueryId?: string,
): DcqlMatcherPresentation {
	return {
		credentialQueryId,
		format: "dc+sd-jwt",
		claims: { vct: "urn:example:pid", ...claims },
		holderBinding: true,
	};
}

describe("haip - DCQL matcher", () => {
	it("matches required claims and values", async () => {
		const query = {
			credentials: [
				{
					id: "pid",
					format: "dc+sd-jwt",
					meta: { vct_values: ["urn:example:pid"] },
					claims: [
						{ path: ["given_name"] },
						{ path: ["address", "country"], values: ["DE"] },
					],
				},
			],
		};
		const ok = await match({
			query,
			presentations: [
				presentation(
					{ given_name: "Erika", address: { country: "DE" } },
					"pid",
				),
			],
		});
		expect(ok.matched).toBe(true);

		const wrongValue = await match({
			query,
			presentations: [
				presentation(
					{ given_name: "Erika", address: { country: "FR" } },
					"pid",
				),
			],
		});
		expect(wrongValue.matched).toBe(false);
		expect(wrongValue.errors?.[0]).toContain('"pid"');
	});

	it("rejects a vct outside vct_values", async () => {
		const result = await match({
			query: {
				credentials: [
					{
						id: "pid",
						format: "dc+sd-jwt",
						meta: { vct_values: ["urn:other"] },
					},
				],
			},
			presentations: [presentation({}, "pid")],
		});
		expect(result.matched).toBe(false);
	});

	it("evaluates claim_sets", async () => {
		const query = {
			credentials: [
				{
					id: "pid",
					format: "dc+sd-jwt",
					meta: { vct_values: ["urn:example:pid"] },
					claims: [
						{ id: "birthdate", path: ["birthdate"] },
						{ id: "over18", path: ["age_over_18"] },
					],
					claim_sets: [["over18"], ["birthdate"]],
				},
			],
		};
		const viaAlternative = await match({
			query,
			presentations: [presentation({ birthdate: "1990-01-01" }, "pid")],
		});
		expect(viaAlternative.matched).toBe(true);
		const neither = await match({
			query,
			presentations: [presentation({ name: "x" }, "pid")],
		});
		expect(neither.matched).toBe(false);
	});

	it("evaluates credential_sets", async () => {
		const query = {
			credentials: [
				{
					id: "pid",
					format: "dc+sd-jwt",
					meta: { vct_values: ["urn:example:pid"] },
				},
				{
					id: "mdl",
					format: "dc+sd-jwt",
					meta: { vct_values: ["urn:example:mdl"] },
				},
			],
			credential_sets: [{ options: [["pid"], ["mdl"]], required: true }],
		};
		const pidOnly = await match({
			query,
			presentations: [presentation({}, "pid")],
		});
		expect(pidOnly.matched).toBe(true);
		const none = await match({ query, presentations: [] });
		expect(none.matched).toBe(false);
	});

	it("enforces multiple", async () => {
		const query = {
			credentials: [
				{
					id: "pid",
					format: "dc+sd-jwt",
					meta: { vct_values: ["urn:example:pid"] },
				},
			],
		};
		const twice = await match({
			query,
			presentations: [presentation({}, "pid"), presentation({}, "pid")],
		});
		expect(twice.matched).toBe(false);
		const allowed = await match({
			query: { credentials: [{ ...query.credentials[0]!, multiple: true }] },
			presentations: [presentation({}, "pid"), presentation({}, "pid")],
		});
		expect(allowed.matched).toBe(true);
	});

	it("assigns unkeyed presentations to a single credential query", async () => {
		const result = await match({
			query: JSON.stringify({
				credentials: [
					{
						id: "pid",
						format: "dc+sd-jwt",
						meta: { vct_values: ["urn:example:pid"] },
					},
				],
			}),
			presentations: [presentation({})],
		});
		expect(result.matched).toBe(true);
	});

	it("rejects an invalid query", async () => {
		const result = await match({
			query: { credentials: [] },
			presentations: [],
		});
		expect(result.matched).toBe(false);
		expect(result.errors?.[0]).toContain("invalid dcql_query");
	});
});
