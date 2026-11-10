import { describe, expect, it } from "vitest";
import {
	CONFIG_ID,
	CREDENTIAL_URL,
	createDpopKey,
	createDpopProof,
	createIssuer,
	createJwtProof,
} from "./issuer";

describe("oidc4vci - DPoP at the credential endpoint", async () => {
	const issuer = await createIssuer();

	async function boundRequest() {
		const dpop = await createDpopKey();
		const { tokens } = await issuer.issueAccessToken({ dpop });
		const { proofJwt } = await createJwtProof({ nonce: await issuer.nonce() });
		const body = {
			credential_configuration_id: CONFIG_ID,
			proofs: { jwt: [proofJwt] },
		};
		return { dpop, accessToken: tokens.access_token, body };
	}

	async function expectDpopRejection(res: Response, reason: string) {
		expect(res.status).toBe(401);
		const body = (await res.json()) as {
			error?: string;
			error_description?: string;
		};
		expect(["invalid_dpop_proof", "invalid_token"]).toContain(body.error);
		expect(body.error_description).toContain(reason);
		expect(res.headers.get("www-authenticate")).toMatch(/^DPoP /);
	}

	it("accepts a DPoP-bound token with a valid proof", async () => {
		const { dpop, accessToken, body } = await boundRequest();
		const res = await issuer.requestCredential({ accessToken, body, dpop });
		expect(res.status).toBe(200);
	});

	it("rejects a DPoP-bound token without a proof", async () => {
		const { accessToken, body } = await boundRequest();
		await expectDpopRejection(
			await issuer.requestCredential({ accessToken, body, scheme: "DPoP" }),
			"proof header is required",
		);
	});

	it("rejects a DPoP-bound token presented as a bearer token", async () => {
		const { dpop, accessToken, body } = await boundRequest();
		const dpopProof = await createDpopProof(dpop, {
			url: CREDENTIAL_URL,
			accessToken,
		});
		await expectDpopRejection(
			await issuer.requestCredential({
				accessToken,
				body,
				dpopProof,
				scheme: "Bearer",
			}),
			"DPoP authorization scheme",
		);
	});

	it("rejects a proof with the wrong htu", async () => {
		const { dpop, accessToken, body } = await boundRequest();
		const dpopProof = await createDpopProof(dpop, {
			url: "https://attacker.example/oidc4vci/credential",
			accessToken,
		});
		await expectDpopRejection(
			await issuer.requestCredential({ accessToken, body, dpopProof }),
			"htu",
		);
	});

	it("rejects a proof with the wrong htm", async () => {
		const { dpop, accessToken, body } = await boundRequest();
		const dpopProof = await createDpopProof(dpop, {
			method: "GET",
			url: CREDENTIAL_URL,
			accessToken,
		});
		await expectDpopRejection(
			await issuer.requestCredential({ accessToken, body, dpopProof }),
			"htm",
		);
	});

	it("rejects a proof with a stale iat", async () => {
		const { dpop, accessToken, body } = await boundRequest();
		const dpopProof = await createDpopProof(dpop, {
			url: CREDENTIAL_URL,
			accessToken,
			iat: Math.floor(Date.now() / 1000) - 3600,
		});
		await expectDpopRejection(
			await issuer.requestCredential({ accessToken, body, dpopProof }),
			"iat",
		);
	});

	it("rejects a replayed proof jti", async () => {
		const { dpop, accessToken, body } = await boundRequest();
		const dpopProof = await createDpopProof(dpop, {
			url: CREDENTIAL_URL,
			accessToken,
		});
		// The first request fails on its proof-of-possession body, after the
		// DPoP proof is accepted and its jti reserved.
		const first = await issuer.requestCredential({
			accessToken,
			body: { ...body, proofs: { jwt: ["invalid"] } },
			dpopProof,
		});
		expect(first.status).toBe(400);
		await expectDpopRejection(
			await issuer.requestCredential({ accessToken, body, dpopProof }),
			"already been used",
		);
	});

	it("rejects a proof with the wrong ath", async () => {
		const { dpop, accessToken, body } = await boundRequest();
		const dpopProof = await createDpopProof(dpop, {
			url: CREDENTIAL_URL,
			accessToken: "another-access-token",
		});
		await expectDpopRejection(
			await issuer.requestCredential({ accessToken, body, dpopProof }),
			"ath",
		);
	});

	it("rejects a proof signed by a key other than the bound one", async () => {
		const { accessToken, body } = await boundRequest();
		const other = await createDpopKey();
		await expectDpopRejection(
			await issuer.requestCredential({ accessToken, body, dpop: other }),
			"does not match the bound token",
		);
	});
});

describe("oidc4vci - required DPoP", async () => {
	const issuer = await createIssuer({
		oidc4vci: { dpop: { required: true, signingAlgorithms: ["ES256"] } },
	});

	it("rejects an unbound access token", async () => {
		const { tokens } = await issuer.issueAccessToken();
		const { proofJwt } = await createJwtProof({ nonce: await issuer.nonce() });
		const res = await issuer.requestCredential({
			accessToken: tokens.access_token,
			body: {
				credential_configuration_id: CONFIG_ID,
				proofs: { jwt: [proofJwt] },
			},
		});
		expect(res.status).toBe(401);
		expect((await res.json()).error).toBe("invalid_token");
	});

	it("rejects a DPoP proof outside the configured algorithms", async () => {
		// The token endpoint accepts EdDSA; the credential endpoint only ES256.
		const dpop = await createDpopKey("EdDSA");
		const { tokens } = await issuer.issueAccessToken({ dpop });
		const { proofJwt } = await createJwtProof({ nonce: await issuer.nonce() });
		const res = await issuer.requestCredential({
			accessToken: tokens.access_token,
			body: {
				credential_configuration_id: CONFIG_ID,
				proofs: { jwt: [proofJwt] },
			},
			dpop,
		});
		expect(res.status).toBe(401);
		expect((await res.json()).error_description).toContain("algorithm");
	});
});
