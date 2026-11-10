import { getListFromStatusListJWT } from "@owf/token-status-list";
import { createLocalJWKSet, decodeJwt, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";
import {
	AUTH_BASE_URL,
	BASE_URL,
	CONFIG_ID,
	createIssuer,
	createJwtProof,
	readCredential,
} from "./issuer";

function parseSdJwt(credential: string) {
	const [jwt, ...disclosures] = credential.split("~");
	const disclosedClaims = disclosures
		.filter(Boolean)
		.map(
			(entry) =>
				JSON.parse(Buffer.from(entry, "base64url").toString("utf8")) as [
					string,
					string,
					unknown,
				],
		)
		.map((entry) => entry[1]);
	return { payload: decodeJwt(jwt!), disclosedClaims };
}

describe("oidc4vci - credential endpoint", async () => {
	const issuer = await createIssuer();
	const getJwks = issuer.auth.api.getJwks;

	async function credentialRequest(
		body: (proofJwt: string) => Record<string, unknown>,
		proofInput?: Parameters<typeof createJwtProof>[0],
	) {
		const { tokens } = await issuer.issueAccessToken();
		const { proofJwt, jwk } = await createJwtProof({
			nonce: await issuer.nonce(),
			...proofInput,
		});
		const res = await issuer.requestCredential({
			accessToken: tokens.access_token,
			body: body(proofJwt),
		});
		return { res, jwk, tokens, proofJwt };
	}

	it("issues an SD-JWT VC bound to the proof key with cnf.jwk", async () => {
		const { res, jwk } = await credentialRequest((proofJwt) => ({
			credential_configuration_id: CONFIG_ID,
			proofs: { jwt: [proofJwt] },
		}));
		expect(res.status).toBe(200);
		const credential = readCredential(await res.json());
		const [sdJwt] = credential.split("~");
		const verified = await jwtVerify(
			sdJwt!,
			createLocalJWKSet(await getJwks({})),
			{ issuer: BASE_URL },
		);
		expect(verified.payload.vct).toBe("urn:example:kyc:v1");
		expect(verified.payload.cnf).toEqual({ jwk });
		const { disclosedClaims } = parseSdJwt(credential);
		expect(disclosedClaims).toContain("email");
		expect(verified.payload.email).toBeUndefined();
	});

	/**
	 * @see https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.1
	 */
	it("returns a c_nonce for an empty POST without a content type", async () => {
		const res = await issuer.customFetchImpl(
			`${AUTH_BASE_URL}/oidc4vci/nonce`,
			{
				method: "POST",
				body: new Uint8Array(),
			},
		);
		expect(res.status).toBe(200);
		expect(res.headers.get("cache-control")).toBe("no-store");
		expect((await res.json()).c_nonce).toBeTypeOf("string");
	});

	it("accepts the credential_identifier from the token response", async () => {
		const { tokens } = await issuer.issueAccessToken();
		const credentialIdentifier =
			tokens.authorization_details?.[0]?.credential_identifiers?.[0];
		const { proofJwt } = await createJwtProof({ nonce: await issuer.nonce() });
		const res = await issuer.requestCredential({
			accessToken: tokens.access_token,
			body: {
				credential_identifier: credentialIdentifier,
				proofs: { jwt: [proofJwt] },
			},
		});
		expect(res.status).toBe(200);

		const { proofJwt: second } = await createJwtProof({
			nonce: await issuer.nonce(),
		});
		const reuse = await issuer.requestCredential({
			accessToken: tokens.access_token,
			body: {
				credential_identifier: credentialIdentifier,
				proofs: { jwt: [second] },
			},
		});
		expect(reuse.status).toBe(400);
		expect((await reuse.json()).error).toBe("unknown_credential_identifier");
	});

	it("consumes a c_nonce once, including under concurrent requests", async () => {
		const { tokens } = await issuer.issueAccessToken();
		const { proofJwt } = await createJwtProof({ nonce: await issuer.nonce() });
		const body = {
			credential_configuration_id: CONFIG_ID,
			proofs: { jwt: [proofJwt] },
		};
		const results = await Promise.all(
			Array.from({ length: 3 }, () =>
				issuer.requestCredential({ accessToken: tokens.access_token, body }),
			),
		);
		const statuses = results.map((res) => res.status);
		expect(statuses.filter((status) => status === 200)).toHaveLength(1);
		const failure = results.find((res) => res.status === 400);
		expect((await failure?.json())?.error).toBe("invalid_nonce");
	});

	it("serves a non-cacheable Nonce Response with only c_nonce", async () => {
		const { res, body } = await issuer.requestNonce();
		expect(res.status).toBe(200);
		expect(res.headers.get("cache-control")).toContain("no-store");
		expect(Object.keys(body)).toEqual(["c_nonce"]);
	});

	it("rejects the removed singular proof parameter", async () => {
		const { res } = await credentialRequest((proofJwt) => ({
			credential_configuration_id: CONFIG_ID,
			proof: { proof_type: "jwt", jwt: proofJwt },
		}));
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("invalid_credential_request");
	});

	it("rejects format-based credential requests", async () => {
		const { res } = await credentialRequest((proofJwt) => ({
			format: "dc+sd-jwt",
			vct: "urn:example:kyc:v1",
			proofs: { jwt: [proofJwt] },
		}));
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("invalid_credential_request");
	});

	it("rejects several proofs while batch issuance is unsupported", async () => {
		const { tokens } = await issuer.issueAccessToken();
		const first = await createJwtProof({ nonce: await issuer.nonce() });
		const second = await createJwtProof({ nonce: await issuer.nonce() });
		const res = await issuer.requestCredential({
			accessToken: tokens.access_token,
			body: {
				credential_configuration_id: CONFIG_ID,
				proofs: { jwt: [first.proofJwt, second.proofJwt] },
			},
		});
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("invalid_proof");
	});

	it("rejects missing proofs and unknown proof types", async () => {
		const { tokens } = await issuer.issueAccessToken();
		const missing = await issuer.requestCredential({
			accessToken: tokens.access_token,
			body: { credential_configuration_id: CONFIG_ID },
		});
		expect((await missing.json()).error).toBe("invalid_proof");
		const unknown = await issuer.requestCredential({
			accessToken: tokens.access_token,
			body: {
				credential_configuration_id: CONFIG_ID,
				proofs: { attestation: ["a.b.c"] },
			},
		});
		expect((await unknown.json()).error).toBe("invalid_proof");
	});

	it.each([
		["a wrong typ", { typ: "JWT" }],
		["a missing jwk header", { omitJwk: true }],
		["the wrong audience", { audience: "https://other.example" }],
		["a stale iat", { iat: Math.floor(Date.now() / 1000) - 3600 }],
		["an iat in the future", { iat: Math.floor(Date.now() / 1000) + 3600 }],
	])("rejects a jwt proof with %s", async (_label, proofInput) => {
		const { res } = await credentialRequest(
			(proofJwt) => ({
				credential_configuration_id: CONFIG_ID,
				proofs: { jwt: [proofJwt] },
			}),
			proofInput,
		);
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("invalid_proof");
	});

	it("rejects HS-signed and unsigned proofs", async () => {
		const { tokens } = await issuer.issueAccessToken();
		const nonce = await issuer.nonce();
		const encode = (value: object) =>
			Buffer.from(JSON.stringify(value)).toString("base64url");
		const payload = encode({
			nonce,
			aud: BASE_URL,
			iat: Math.floor(Date.now() / 1000),
		});
		for (const alg of ["HS256", "none"]) {
			const header = encode({
				alg,
				typ: "openid4vci-proof+jwt",
				jwk: { kty: "oct", k: "c2VjcmV0" },
			});
			const res = await issuer.requestCredential({
				accessToken: tokens.access_token,
				body: {
					credential_configuration_id: CONFIG_ID,
					proofs: { jwt: [`${header}.${payload}.c2ln`] },
				},
			});
			expect((await res.json()).error).toBe("invalid_proof");
		}
	});

	it("rejects a proof signed by a key other than its jwk header", async () => {
		const { tokens } = await issuer.issueAccessToken();
		const nonce = await issuer.nonce();
		const signer = await createJwtProof({ nonce });
		const other = await createJwtProof({ nonce });
		const [header] = other.proofJwt.split(".");
		const [, payload, signature] = signer.proofJwt.split(".");
		const res = await issuer.requestCredential({
			accessToken: tokens.access_token,
			body: {
				credential_configuration_id: CONFIG_ID,
				proofs: { jwt: [`${header}.${payload}.${signature}`] },
			},
		});
		expect((await res.json()).error).toBe("invalid_proof");
	});

	it("rejects an unknown c_nonce", async () => {
		const { res } = await credentialRequest(
			(proofJwt) => ({
				credential_configuration_id: CONFIG_ID,
				proofs: { jwt: [proofJwt] },
			}),
			{ nonce: "not-issued" },
		);
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("invalid_nonce");
	});

	it("validates the credential selector", async () => {
		const { tokens } = await issuer.issueAccessToken();
		const proof = async () =>
			(await createJwtProof({ nonce: await issuer.nonce() })).proofJwt;
		const unknownConfig = await issuer.requestCredential({
			accessToken: tokens.access_token,
			body: {
				credential_configuration_id: "unknown",
				proofs: { jwt: [await proof()] },
			},
		});
		expect((await unknownConfig.json()).error).toBe(
			"unknown_credential_configuration",
		);
		const unknownIdentifier = await issuer.requestCredential({
			accessToken: tokens.access_token,
			body: {
				credential_identifier: "unknown",
				proofs: { jwt: [await proof()] },
			},
		});
		expect((await unknownIdentifier.json()).error).toBe(
			"unknown_credential_identifier",
		);
		const both = await issuer.requestCredential({
			accessToken: tokens.access_token,
			body: {
				credential_identifier: "x",
				credential_configuration_id: CONFIG_ID,
				proofs: { jwt: [await proof()] },
			},
		});
		expect((await both.json()).error).toBe("invalid_credential_request");
		const neither = await issuer.requestCredential({
			accessToken: tokens.access_token,
			body: { proofs: { jwt: [await proof()] } },
		});
		expect((await neither.json()).error).toBe("invalid_credential_request");
	});

	it("rejects requests without a valid access token", async () => {
		const { proofJwt } = await createJwtProof({ nonce: await issuer.nonce() });
		const res = await issuer.requestCredential({
			accessToken: "not-a-token",
			body: {
				credential_configuration_id: CONFIG_ID,
				proofs: { jwt: [proofJwt] },
			},
		});
		expect(res.status).toBe(401);
		expect(res.headers.get("www-authenticate")).toContain("invalid_token");
	});

	it("honors requested claims for selective disclosure", async () => {
		const { tokens } = await issuer.issueAccessToken({
			offer: {
				claims: [{ path: ["email"], mandatory: true }, { path: ["name"] }],
			},
		});
		const { proofJwt } = await createJwtProof({ nonce: await issuer.nonce() });
		const res = await issuer.requestCredential({
			accessToken: tokens.access_token,
			body: {
				credential_configuration_id: CONFIG_ID,
				proofs: { jwt: [proofJwt] },
			},
		});
		expect(res.status).toBe(200);
		const { payload, disclosedClaims } = parseSdJwt(
			readCredential(await res.json()),
		);
		expect(payload.email).toBeTypeOf("string");
		expect(payload.name).toBeUndefined();
		expect(disclosedClaims).toContain("name");
		expect(disclosedClaims).not.toContain("email_verified");
	});

	it("allocates distinct status list indices under concurrent issuance", async () => {
		const requests = await Promise.all(
			Array.from({ length: 4 }, async () => {
				const { tokens } = await issuer.issueAccessToken();
				const { proofJwt } = await createJwtProof({
					nonce: await issuer.nonce(),
				});
				return { tokens, proofJwt };
			}),
		);
		const responses = await Promise.all(
			requests.map(({ tokens, proofJwt }) =>
				issuer.requestCredential({
					accessToken: tokens.access_token,
					body: {
						credential_configuration_id: CONFIG_ID,
						proofs: { jwt: [proofJwt] },
					},
				}),
			),
		);
		const indices = await Promise.all(
			responses.map(async (res) => {
				const { payload } = parseSdJwt(readCredential(await res.json()));
				return (payload.status as { status_list: { idx: number } }).status_list
					.idx;
			}),
		);
		expect(new Set(indices).size).toBe(indices.length);
	});

	it("publishes status and lets the holder revoke, but not restore, a credential", async () => {
		const { tokens, headers, user } = await issuer.issueAccessToken();
		const { proofJwt } = await createJwtProof({ nonce: await issuer.nonce() });
		const res = await issuer.requestCredential({
			accessToken: tokens.access_token,
			body: {
				credential_configuration_id: CONFIG_ID,
				proofs: { jwt: [proofJwt] },
			},
		});
		const { payload } = parseSdJwt(readCredential(await res.json()));
		const { idx, uri } = (
			payload.status as { status_list: { idx: number; uri: string } }
		).status_list;

		const listRes = await issuer.customFetchImpl(uri, { method: "GET" });
		expect(listRes.headers.get("content-type")).toContain(
			"application/statuslist+jwt",
		);
		expect(getListFromStatusListJWT(await listRes.text()).getStatus(idx)).toBe(
			0,
		);

		const { adapter } = await issuer.auth.$context;
		const [record] = await adapter.findMany<{ id: string }>({
			model: "oidc4vciIssuedCredential",
			where: [
				{ field: "userId", value: user.id },
				{ field: "statusListIndex", value: idx },
			],
		});
		const updateCredentialStatus = issuer.auth.api.updateCredentialStatus;
		await updateCredentialStatus({
			headers,
			body: { credential_id: record!.id, status: 1 },
		});
		const listRes2 = await issuer.customFetchImpl(uri, { method: "GET" });
		expect(getListFromStatusListJWT(await listRes2.text()).getStatus(idx)).toBe(
			1,
		);

		await expect(
			updateCredentialStatus({
				headers,
				body: { credential_id: record!.id, status: 0 },
			}),
		).rejects.toMatchObject({ status: "FORBIDDEN" });
	});
});
