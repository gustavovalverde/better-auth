import { createDpopNonce } from "@better-auth/core/oauth2";
import { describe, expect, it, vi } from "vitest";
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

describe("oidc4vci - DPoP nonces", async () => {
	const issuer = await createIssuer({
		dpop: { nonce: { required: true } },
	});

	async function boundRequest() {
		const dpop = await createDpopKey();
		const { tokens } = await issuer.issueAccessToken({ dpop });
		return { dpop, accessToken: tokens.access_token };
	}

	async function credentialBody() {
		const { proofJwt } = await createJwtProof({ nonce: await issuer.nonce() });
		return {
			credential_configuration_id: CONFIG_ID,
			proofs: { jwt: [proofJwt] },
		};
	}

	async function expectNonceChallenge(res: Response) {
		expect(res.status).toBe(401);
		expect((await res.json()).error).toBe("use_dpop_nonce");
		expect(res.headers.get("www-authenticate")).toMatch(
			/^DPoP error="use_dpop_nonce", error_description="[^"]+", algs="/,
		);
		expect(res.headers.get("cache-control")).toContain("no-store");
		expect(res.headers.get("access-control-expose-headers")).toContain(
			"DPoP-Nonce",
		);
		const nonce = res.headers.get("dpop-nonce");
		expect(nonce).toBeTruthy();
		return nonce!;
	}

	it("asks for a nonce, accepts the retry, and sends the next nonce", async () => {
		const { dpop, accessToken } = await boundRequest();
		const body = await credentialBody();

		const nonce = await expectNonceChallenge(
			await issuer.requestCredential({ accessToken, body, dpop }),
		);
		const retried = await issuer.requestCredential({
			accessToken,
			body,
			dpop,
			dpopNonce: nonce,
		});
		expect(retried.status).toBe(200);
		expect(retried.headers.get("cache-control")).toContain("no-store");
		const next = retried.headers.get("dpop-nonce");
		expect(next).toBeTruthy();

		const again = await boundRequest();
		const reused = await issuer.requestCredential({
			accessToken: again.accessToken,
			body: await credentialBody(),
			dpop: again.dpop,
			dpopNonce: next!,
		});
		expect(reused.status).toBe(200);
	});

	it("accepts the nonce the token endpoint issued", async () => {
		const dpop = await createDpopKey();
		const session = await issuer.signInWithTestUser();
		const clientId = await issuer.createWalletClient(session.headers);
		const { code } = await issuer.createOffer(session.headers, {
			client_id: clientId,
			credential_configuration_id: CONFIG_ID,
		});
		const tokenResponse = await issuer.redeem({ code, clientId, dpop });
		expect(tokenResponse.status).toBe(200);
		const { access_token } = (await tokenResponse.json()) as {
			access_token: string;
		};

		const res = await issuer.requestCredential({
			accessToken: access_token,
			body: await credentialBody(),
			dpop,
			dpopNonce: tokenResponse.headers.get("dpop-nonce")!,
		});
		expect(res.status).toBe(200);
	});

	it("refuses a nonce from another secret or past its lifetime", async () => {
		const { dpop, accessToken } = await boundRequest();
		const body = await credentialBody();
		const secret = (await issuer.auth.$context).secret;
		const foreign = await createDpopNonce({ secret: "another-secret-value" });
		const clock = vi.spyOn(Date, "now").mockReturnValue(Date.now() - 600_000);
		const stale = await createDpopNonce({ secret });
		clock.mockRestore();

		for (const dpopNonce of [foreign, stale]) {
			await expectNonceChallenge(
				await issuer.requestCredential({ accessToken, body, dpop, dpopNonce }),
			);
		}
		// A refused proof consumes nothing.
		const current = await createDpopNonce({ secret });
		const res = await issuer.requestCredential({
			accessToken,
			body,
			dpop,
			dpopNonce: current,
		});
		expect(res.status).toBe(200);
	});

	it("leaves bearer tokens alone", async () => {
		const { tokens } = await issuer.issueAccessToken();
		const res = await issuer.requestCredential({
			accessToken: tokens.access_token,
			body: await credentialBody(),
		});
		expect(res.status).toBe(200);
		expect(res.headers.get("dpop-nonce")).toBeNull();
	});
});
