import { createInMemoryDpopReplayStore } from "@better-auth/core/oauth2";
import { describe, expect, it } from "vitest";
import { createDpopAccessTokenValidator } from "../src";
import { createDpopKey, createDpopProof } from "./haip-server";

const RESOURCE_URL = "https://rs.example/api/resource";
const ACCESS_TOKEN = "access-token-value";

async function resourceRequest(input: {
	scheme?: "Bearer" | "DPoP";
	proof?: string;
	url?: string;
	method?: string;
}) {
	const headers = new Headers({
		authorization: `${input.scheme ?? "DPoP"} ${ACCESS_TOKEN}`,
	});
	if (input.proof) headers.set("dpop", input.proof);
	return new Request(input.url ?? RESOURCE_URL, {
		method: input.method ?? "GET",
		headers,
	});
}

async function rejection(promise: Promise<unknown>) {
	const error = (await promise.then(
		() => undefined,
		(cause: unknown) => cause,
	)) as {
		status?: string;
		body?: { error?: string; error_description?: string };
	};
	expect(error?.status).toBe("UNAUTHORIZED");
	return error.body?.error_description ?? "";
}

describe("haip - DPoP resource validator", async () => {
	const key = await createDpopKey();
	const tokenPayload = { sub: "user", cnf: { jkt: key.jkt } };
	const proof = (input?: Partial<Parameters<typeof createDpopProof>[1]>) =>
		createDpopProof(key, {
			method: "GET",
			url: RESOURCE_URL,
			accessToken: ACCESS_TOKEN,
			...input,
		});

	it("accepts a valid proof for a bound token", async () => {
		const validate = createDpopAccessTokenValidator();
		const request = await resourceRequest({ proof: await proof() });
		await expect(validate({ request, tokenPayload })).resolves.toBeUndefined();
	});

	it("rejects a proof with the wrong htu", async () => {
		const validate = createDpopAccessTokenValidator();
		const request = await resourceRequest({
			proof: await proof({ url: "https://rs.example/api/other" }),
		});
		expect(await rejection(validate({ request, tokenPayload }))).toContain(
			"htu",
		);
	});

	it("rejects a proof with a stale iat", async () => {
		const validate = createDpopAccessTokenValidator();
		const request = await resourceRequest({
			proof: await proof({ iat: Math.floor(Date.now() / 1000) - 3600 }),
		});
		expect(await rejection(validate({ request, tokenPayload }))).toContain(
			"iat",
		);
	});

	it("rejects a replayed proof jti", async () => {
		const validate = createDpopAccessTokenValidator({
			replayStore: createInMemoryDpopReplayStore(),
		});
		const dpopProof = await proof();
		await validate({
			request: await resourceRequest({ proof: dpopProof }),
			tokenPayload,
		});
		expect(
			await rejection(
				validate({
					request: await resourceRequest({ proof: dpopProof }),
					tokenPayload,
				}),
			),
		).toContain("already been used");
	});

	it("rejects a proof with the wrong ath", async () => {
		const validate = createDpopAccessTokenValidator();
		const request = await resourceRequest({
			proof: await proof({ accessToken: "another-token" }),
		});
		expect(await rejection(validate({ request, tokenPayload }))).toContain(
			"ath",
		);
	});

	it("rejects a bound token presented with the Bearer scheme", async () => {
		const validate = createDpopAccessTokenValidator();
		const request = await resourceRequest({
			scheme: "Bearer",
			proof: await proof(),
		});
		expect(await rejection(validate({ request, tokenPayload }))).toContain(
			"DPoP authorization scheme",
		);
	});

	it("rejects a proof signed by another key", async () => {
		const validate = createDpopAccessTokenValidator();
		const other = await createDpopKey();
		const request = await resourceRequest({
			proof: await createDpopProof(other, {
				method: "GET",
				url: RESOURCE_URL,
				accessToken: ACCESS_TOKEN,
			}),
		});
		expect(await rejection(validate({ request, tokenPayload }))).toContain(
			"does not match",
		);
	});

	it("only accepts ES256 proofs by default", async () => {
		const validate = createDpopAccessTokenValidator();
		const edKey = await createDpopKey("EdDSA");
		const request = await resourceRequest({
			proof: await createDpopProof(edKey, {
				method: "GET",
				url: RESOURCE_URL,
				accessToken: ACCESS_TOKEN,
			}),
		});
		expect(
			await rejection(
				validate({ request, tokenPayload: { cnf: { jkt: edKey.jkt } } }),
			),
		).toContain("algorithm");
		const permissive = createDpopAccessTokenValidator({
			signingAlgorithms: ["ES256", "EdDSA"],
		});
		await expect(
			permissive({ request, tokenPayload: { cnf: { jkt: edKey.jkt } } }),
		).resolves.toBeUndefined();
	});

	it("rejects an unbound token when DPoP is required", async () => {
		const validate = createDpopAccessTokenValidator({ requireDpop: true });
		const request = await resourceRequest({ scheme: "Bearer" });
		expect(
			await rejection(validate({ request, tokenPayload: { sub: "u" } })),
		).toContain("DPoP-bound access token required");
		const optional = createDpopAccessTokenValidator();
		await expect(
			optional({ request, tokenPayload: { sub: "u" } }),
		).resolves.toBeUndefined();
	});
});
