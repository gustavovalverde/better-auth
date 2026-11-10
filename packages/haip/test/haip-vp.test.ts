import type { JWK } from "jose";
import {
	CompactEncrypt,
	compactVerify,
	decodeJwt,
	decodeProtectedHeader,
	exportJWK,
	generateKeyPair,
	importJWK,
	SignJWT,
} from "jose";
import { describe, expect, it } from "vitest";
import {
	computeX509Hash,
	createDcqlMatcher,
	createJarmHandler,
	createVpSessionResolver,
} from "../src";
import { AUTH_BASE_URL, createHaipServer, sha256, VCT } from "./haip-server";
import { caCert, leafCert, leafKey, rogueKey } from "./x509-fixtures";

const DCQL_QUERY = {
	credentials: [
		{
			id: "kyc",
			format: "dc+sd-jwt",
			meta: { vct_values: [VCT] },
			claims: [{ path: ["email"] }],
		},
	],
};

describe("haip - OpenID4VP requests and encrypted responses", async () => {
	const encryption = await generateKeyPair("ECDH-ES", {
		crv: "P-256",
		extractable: true,
	});
	const encryptionJwk = {
		...(await exportJWK(encryption.publicKey)),
		kid: "enc-1",
		use: "enc",
		alg: "ECDH-ES",
	};
	const decryptionJwk = {
		...(await exportJWK(encryption.privateKey)),
		kid: "enc-1",
	};
	const server = await createHaipServer({
		haip: {
			verifier: {
				x5c: [leafCert, caCert],
				signingKey: leafKey as JWK,
				encryptionKeys: [encryptionJwk],
			},
		},
		oidc4vp: {
			resolveAuthorizationRequest: createVpSessionResolver(),
			presentationMatcher: createDcqlMatcher(),
			responseModeHandlers: {
				"direct_post.jwt": createJarmHandler({ decryptionKey: decryptionJwk }),
			},
		},
	});
	const createVpRequest = server.auth.api.createHaipVpRequest;

	async function present(input: { nonce: string; aud: string }) {
		const { credential, holder } = await server.issueCredential();
		const kb = await new SignJWT({
			nonce: input.nonce,
			sd_hash: await sha256(credential),
		})
			.setProtectedHeader({ alg: "ES256", typ: "kb+jwt" })
			.setIssuedAt()
			.setAudience(input.aud)
			.sign(holder.privateKey);
		return `${credential}${kb}`;
	}

	async function encryptResponse(
		payload: Record<string, unknown>,
		enc = "A128GCM",
	) {
		return new CompactEncrypt(new TextEncoder().encode(JSON.stringify(payload)))
			.setProtectedHeader({ alg: "ECDH-ES", enc, kid: "enc-1" })
			.encrypt(await importJWK(encryptionJwk, "ECDH-ES"));
	}

	it("signs request objects with the x509_hash Client Identifier Prefix", async () => {
		const request = await createVpRequest({ body: { dcql_query: DCQL_QUERY } });
		const expectedClientId = `x509_hash:${await computeX509Hash(leafCert)}`;
		expect(request.client_id).toBe(expectedClientId);
		const authorizationRequest = new URL(request.authorization_request);
		expect(authorizationRequest.protocol).toBe("openid4vp:");
		expect(authorizationRequest.searchParams.get("client_id")).toBe(
			expectedClientId,
		);
		expect(authorizationRequest.searchParams.get("request_uri")).toBe(
			request.request_uri,
		);
		expect(authorizationRequest.searchParams.has("client_id_scheme")).toBe(
			false,
		);

		const res = await server.customFetchImpl(request.request_uri);
		expect(res.status).toBe(200);
		expect(res.headers.get("content-type")).toBe(
			"application/oauth-authz-req+jwt",
		);
		const jwt = await res.text();
		const header = decodeProtectedHeader(jwt);
		expect(header.typ).toBe("oauth-authz-req+jwt");
		expect(header.x5c).toEqual([leafCert, caCert]);
		const { d: _d, ...leafPublicJwk } = leafKey as JWK;
		await expect(
			compactVerify(jwt, await importJWK(leafPublicJwk, "ES256")),
		).resolves.toBeDefined();

		const payload = decodeJwt(jwt) as Record<string, any>;
		expect(payload).toMatchObject({
			client_id: expectedClientId,
			response_type: "vp_token",
			response_mode: "direct_post.jwt",
			response_uri: `${AUTH_BASE_URL}/oidc4vp/response`,
			nonce: request.nonce,
			state: request.state,
			aud: "https://self-issued.me/v2",
		});
		expect(payload).not.toHaveProperty("client_id_scheme");
		expect(payload.dcql_query.credentials[0].id).toBe("kyc");
		expect(payload.client_metadata.jwks.keys[0].kid).toBe("enc-1");
		expect(payload.client_metadata.jwks.keys[0]).not.toHaveProperty("d");
	});

	it("does not expose VP request creation over HTTP", async () => {
		const res = await server.customFetchImpl(
			`${AUTH_BASE_URL}/haip/vp/request`,
			{
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ dcql_query: DCQL_QUERY }),
			},
		);
		expect(res.status).toBe(404);
	});

	it("rejects an invalid DCQL query", async () => {
		await expect(
			createVpRequest({ body: { dcql_query: { credentials: [] } } }),
		).rejects.toMatchObject({ status: "BAD_REQUEST" });
	});

	it("verifies an encrypted response against its session", async () => {
		const request = await createVpRequest({ body: { dcql_query: DCQL_QUERY } });
		const vpToken = await present({
			nonce: request.nonce,
			aud: request.client_id,
		});
		const response = await encryptResponse({
			vp_token: { kyc: [vpToken] },
			state: request.state,
		});
		const res = await server.postForm(`${AUTH_BASE_URL}/oidc4vp/response`, {
			response,
		});
		expect(res.status).toBe(200);
		const body = (await res.json()) as {
			verified: boolean;
			state: string;
			presentations: Array<{
				credentialQueryId: string;
				holderBinding: boolean;
			}>;
		};
		expect(body.verified).toBe(true);
		expect(body.state).toBe(request.state);
		expect(body.presentations[0]).toMatchObject({
			credentialQueryId: "kyc",
			holderBinding: true,
		});
	});

	it("rejects a plain direct_post response to a direct_post.jwt request", async () => {
		const request = await createVpRequest({ body: { dcql_query: DCQL_QUERY } });
		const vpToken = await present({
			nonce: request.nonce,
			aud: request.client_id,
		});
		const res = await server.postForm(`${AUTH_BASE_URL}/oidc4vp/response`, {
			vp_token: JSON.stringify({ kyc: [vpToken] }),
			state: request.state,
		});
		expect(res.status).toBe(400);
	});

	it("rejects a presentation bound to another session's nonce", async () => {
		const request = await createVpRequest({ body: { dcql_query: DCQL_QUERY } });
		const other = await createVpRequest({ body: { dcql_query: DCQL_QUERY } });
		const vpToken = await present({
			nonce: other.nonce,
			aud: request.client_id,
		});
		const response = await encryptResponse({
			vp_token: { kyc: [vpToken] },
			state: request.state,
		});
		const res = await server.postForm(`${AUTH_BASE_URL}/oidc4vp/response`, {
			response,
		});
		expect(res.status).toBe(400);
	});

	it("rejects a response encrypted with a disallowed algorithm", async () => {
		const request = await createVpRequest({ body: { dcql_query: DCQL_QUERY } });
		const response = await encryptResponse(
			{ vp_token: { kyc: ["a.b.c"] }, state: request.state },
			"A128CBC-HS256",
		);
		const res = await server.postForm(`${AUTH_BASE_URL}/oidc4vp/response`, {
			response,
		});
		expect(res.status).toBe(400);
	});

	it("returns 404 for an unknown request object", async () => {
		const res = await server.customFetchImpl(
			`${AUTH_BASE_URL}/haip/vp/request-object?session_id=unknown`,
		);
		expect(res.status).toBe(404);
	});
});

describe("haip - verifier configuration", async () => {
	const server = await createHaipServer({
		haip: {
			verifier: { x5c: [leafCert, caCert], signingKey: rogueKey as JWK },
		},
	});

	it("refuses to sign with a key that does not match the leaf certificate", async () => {
		await expect(
			server.auth.api.createHaipVpRequest({
				body: { dcql_query: DCQL_QUERY, response_mode: "direct_post" },
			}),
		).rejects.toThrow("does not match the leaf certificate");
	});
});
