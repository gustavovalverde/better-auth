import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import { BASE_URL, createVerifier, VCT } from "./wallet";

type VerifyBody = {
	verified: boolean;
	state?: string;
	presentations?: Array<{
		issuer?: string;
		credentialQueryId?: string;
		holderBinding?: boolean;
		status?: number;
		claims?: Record<string, unknown>;
	}>;
	errors?: Array<{ index: number; message: string }>;
};

describe("oidc4vp - /oidc4vp/verify", async () => {
	const verifier = await createVerifier();

	it("verifies an SD-JWT VC presentation with holder binding", async () => {
		const vpToken = await verifier.present({ nonce: "nonce-1" });
		const res = await verifier.verify({ vp_token: vpToken, nonce: "nonce-1" });
		expect(res.status).toBe(200);
		const body = (await res.json()) as VerifyBody;
		expect(body.verified).toBe(true);
		expect(body.presentations?.[0]).toMatchObject({
			issuer: BASE_URL,
			holderBinding: true,
			status: 0,
		});
		expect(body.presentations?.[0]?.claims?.vct).toBe(VCT);
	});

	it("keeps the DCQL credential query id of each presentation", async () => {
		const vpToken = await verifier.present({ nonce: "nonce-2" });
		const res = await verifier.verify({
			vp_token: { kyc: [vpToken] },
			nonce: "nonce-2",
		});
		const body = (await res.json()) as VerifyBody;
		expect(body.presentations?.[0]?.credentialQueryId).toBe("kyc");
	});

	it.each([
		["a different nonce", { nonce: "other" }, "nonce-3"],
		[
			"a different audience",
			{ nonce: "nonce-3", aud: "https://rp.example" },
			"nonce-3",
		],
		[
			"a stale key binding",
			{ nonce: "nonce-3", iat: Math.floor(Date.now() / 1000) - 3600 },
			"nonce-3",
		],
	])("rejects a key binding JWT with %s", async (_label, kb, nonce) => {
		const vpToken = await verifier.present(kb);
		const res = await verifier.verify({ vp_token: vpToken, nonce });
		expect(res.status).toBe(400);
		expect(((await res.json()) as VerifyBody).verified).toBe(false);
	});

	it("rejects a presentation without a key binding JWT", async () => {
		const { credential } = await verifier.issueCredential();
		const res = await verifier.verify({ vp_token: credential, nonce: "n" });
		expect(res.status).toBe(400);
	});

	it("rejects a key binding JWT signed by a key other than cnf.jwk", async () => {
		const { credential } = await verifier.issueCredential();
		const other = await verifier.issueCredential();
		const { createKbJwt } = await import("./wallet");
		const kb = await createKbJwt({
			credential,
			holder: other.holder,
			nonce: "n",
			aud: BASE_URL,
		});
		const res = await verifier.verify({
			vp_token: `${credential}${kb}`,
			nonce: "n",
		});
		expect(res.status).toBe(400);
	});

	it("rejects a tampered presentation", async () => {
		const vpToken = await verifier.present({ nonce: "nonce-4" });
		const [jwt, ...rest] = vpToken.split("~");
		const position = jwt!.length - 10;
		const tampered = `${jwt!.slice(0, position)}${jwt![position] === "A" ? "B" : "A"}${jwt!.slice(position + 1)}`;
		const res = await verifier.verify({
			vp_token: [tampered, ...rest].join("~"),
			nonce: "nonce-4",
		});
		expect(res.status).toBe(400);
		expect(((await res.json()) as VerifyBody).errors).toHaveLength(1);
	});
});

describe("oidc4vp - /oidc4vp/response", async () => {
	const verifier = await createVerifier();

	it("verifies a direct_post response against the request its state names", async () => {
		const request = verifier.registerRequest();
		const vpToken = await verifier.present({
			nonce: request.nonce,
			aud: request.client_id,
		});
		const res = await verifier.post("/oidc4vp/response", {
			vp_token: JSON.stringify({ kyc: [vpToken] }),
			state: request.state,
		});
		expect(res.status).toBe(200);
		const body = (await res.json()) as VerifyBody;
		expect(body.verified).toBe(true);
		expect(body.state).toBe(request.state);
		expect(body.presentations?.[0]?.credentialQueryId).toBe("kyc");
	});

	it("uses the request nonce, not one the wallet sends", async () => {
		const request = verifier.registerRequest();
		const vpToken = await verifier.present({
			nonce: "wallet-chosen",
			aud: request.client_id,
		});
		const res = await verifier.post("/oidc4vp/response", {
			vp_token: JSON.stringify({ kyc: [vpToken] }),
			state: request.state,
			nonce: "wallet-chosen",
		});
		expect(res.status).toBe(400);
	});

	it("expects the request's client_id as the key binding audience", async () => {
		const request = verifier.registerRequest();
		const vpToken = await verifier.present({
			nonce: request.nonce,
			aud: BASE_URL,
		});
		const res = await verifier.post("/oidc4vp/response", {
			vp_token: JSON.stringify({ kyc: [vpToken] }),
			state: request.state,
		});
		expect(res.status).toBe(400);
	});

	it("rejects an unknown state", async () => {
		const res = await verifier.post("/oidc4vp/response", {
			vp_token: JSON.stringify({ kyc: ["a.b.c"] }),
			state: "unknown",
		});
		expect(res.status).toBe(400);
		expect((await res.json()).error_description).toContain("state");
	});

	it("rejects a vp_token keyed by a query the request did not ask for", async () => {
		const request = verifier.registerRequest();
		const vpToken = await verifier.present({
			nonce: request.nonce,
			aud: request.client_id,
		});
		const res = await verifier.post("/oidc4vp/response", {
			vp_token: JSON.stringify({ other: [vpToken] }),
			state: request.state,
		});
		expect(res.status).toBe(400);
	});

	it("checks presentations against the request's DCQL query", async () => {
		const strict = await createVerifier({
			presentationMatcher: async ({ query, presentations }) => {
				const vct = (
					query as { credentials: Array<{ meta: { vct_values: string[] } }> }
				).credentials[0]?.meta.vct_values[0];
				const matched = presentations.every(
					(presentation) => presentation.claims.vct === vct,
				);
				return { matched, matchedPresentations: matched ? presentations : [] };
			},
		});
		const request = strict.registerRequest({
			dcql_query: {
				credentials: [
					{
						id: "kyc",
						format: "dc+sd-jwt",
						meta: { vct_values: ["urn:example:other"] },
					},
				],
			},
		});
		const vpToken = await strict.present({
			nonce: request.nonce,
			aud: request.client_id,
		});
		const res = await strict.post("/oidc4vp/response", {
			vp_token: JSON.stringify({ kyc: [vpToken] }),
			state: request.state,
		});
		expect(res.status).toBe(400);
		expect(decodeJwt(vpToken.split("~")[0]!).vct).toBe(VCT);
	});
});

describe("oidc4vp - response endpoint configuration", async () => {
	const verifier = await createVerifier({
		resolveAuthorizationRequest: undefined,
	});

	it("refuses responses when no authorization request resolver is configured", async () => {
		const res = await verifier.post("/oidc4vp/response", {
			vp_token: "a.b.c",
			state: "s",
		});
		expect(res.status).toBe(400);
	});
});
