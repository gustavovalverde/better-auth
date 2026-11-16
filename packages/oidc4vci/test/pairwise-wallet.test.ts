import { symmetricEncrypt } from "better-auth/crypto";
import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import {
	CONFIG_ID,
	CREDENTIAL_URL,
	createDpopKey,
	createIssuer,
	createJwtProof,
	DEFERRED_URL,
	readCredential,
} from "./issuer";

const DEFERRED_CONFIG_ID = "kyc_sdjwt_deferred_v1";

/**
 * A pairwise wallet's access token names the user by a pairwise `sub` and
 * carries the user id only encrypted in `ba_sub`. The credential endpoints
 * read the user from the provider, never from the token's own `sub`.
 */
describe("oidc4vci - pairwise wallets", async () => {
	const validatedPayloads: Record<string, unknown>[] = [];
	const issuer = await createIssuer({
		pairwise: true,
		oidc4vci: {
			credentialConfigurations: [
				{ id: CONFIG_ID, vct: "urn:example:kyc:v1" },
				{ id: DEFERRED_CONFIG_ID, vct: "urn:example:kyc:deferred:v1" },
			],
			deferredIssuance: {
				shouldDefer: ({ credentialConfigurationId }) =>
					credentialConfigurationId === DEFERRED_CONFIG_ID,
				intervalSeconds: 5,
			},
			accessTokenValidator: ({ tokenPayload }) => {
				validatedPayloads.push(tokenPayload);
			},
		},
	});

	async function signUpAnotherUser() {
		const email = `other-${crypto.randomUUID()}@example.com`;
		const password = "password-for-another-user";
		await issuer.auth.api.signUpEmail({
			body: { email, password, name: "Other" },
		});
		return issuer.signInWithUser(email, password);
	}

	async function walletTokens(
		headers: Headers,
		clientId: string,
		credentialConfigurationId = CONFIG_ID,
	) {
		const dpop = await createDpopKey();
		const { code } = await issuer.createOffer(headers, {
			client_id: clientId,
			credential_configuration_id: credentialConfigurationId,
		});
		const tokens = await issuer.redeemTokens({ code, clientId, dpop });
		return { dpop, tokens };
	}

	async function proofBody(body: Record<string, unknown>) {
		const proof = await createJwtProof({ nonce: await issuer.nonce() });
		return { ...proof, body: { ...body, proofs: { jwt: [proof.proofJwt] } } };
	}

	async function storedCredentials(userId: string) {
		const { adapter } = await issuer.auth.$context;
		return adapter.findMany<{ userId: string }>({
			model: "oidc4vciIssuedCredential",
			where: [{ field: "userId", value: userId }],
		});
	}

	it("issues a credential without a subject to a pairwise wallet", async () => {
		const { headers, user } = await issuer.signInWithTestUser();
		const clientId = await issuer.createWalletClient(headers, {
			pairwise: true,
		});
		const { dpop, tokens } = await walletTokens(headers, clientId);
		const accessToken = decodeJwt(tokens.access_token);
		expect(accessToken.sub).toBeTypeOf("string");
		expect(accessToken.sub).not.toBe(user.id);
		expect(accessToken.ba_sub).toBeTypeOf("string");

		const before = (await storedCredentials(user.id)).length;
		const { body, jwk } = await proofBody({
			credential_configuration_id: CONFIG_ID,
		});
		const res = await issuer.requestCredential({
			accessToken: tokens.access_token,
			body,
			dpop,
		});
		expect(res.status).toBe(200);
		const credential = readCredential(await res.json());
		const payload = decodeJwt(credential.split("~")[0]!);
		expect(payload).not.toHaveProperty("sub");
		expect(payload.cnf).toEqual({ jwk });
		expect(credential).not.toContain(user.id);
		expect(credential).not.toContain(accessToken.sub as string);
		// The plugin found the real user: the record is theirs.
		expect(await storedCredentials(user.id)).toHaveLength(before + 1);
	});

	it("gives accessTokenValidator the user id the provider restored", async () => {
		const { headers, user } = await issuer.signInWithTestUser();
		const clientId = await issuer.createWalletClient(headers, {
			pairwise: true,
		});
		const { dpop, tokens } = await walletTokens(headers, clientId);
		validatedPayloads.length = 0;

		const { body } = await proofBody({
			credential_configuration_id: CONFIG_ID,
		});
		const res = await issuer.requestCredential({
			accessToken: tokens.access_token,
			body,
			dpop,
		});
		expect(res.status).toBe(200);
		expect(validatedPayloads).toHaveLength(1);
		expect(validatedPayloads[0]).toMatchObject({
			active: true,
			sub: user.id,
			client_id: clientId,
		});
		expect(validatedPayloads[0]).not.toHaveProperty("ba_sub");
		expect(decodeJwt(tokens.access_token).sub).not.toBe(user.id);
	});

	it("binds a credential_identifier to the user it was issued for", async () => {
		const owner = await issuer.signInWithTestUser();
		const other = await signUpAnotherUser();
		const clientId = await issuer.createWalletClient(owner.headers, {
			pairwise: true,
		});
		const ownerTokens = await walletTokens(owner.headers, clientId);
		const otherTokens = await walletTokens(other.headers, clientId);
		const credentialIdentifier =
			ownerTokens.tokens.authorization_details?.[0]
				?.credential_identifiers?.[0];
		expect(credentialIdentifier).toBeTypeOf("string");

		const stolen = await issuer.requestCredential({
			accessToken: otherTokens.tokens.access_token,
			body: (await proofBody({ credential_identifier: credentialIdentifier }))
				.body,
			dpop: otherTokens.dpop,
		});
		expect(stolen.status).toBe(400);
		expect((await stolen.json()).error).toBe("unknown_credential_identifier");

		const own = await issuer.requestCredential({
			accessToken: ownerTokens.tokens.access_token,
			body: (await proofBody({ credential_identifier: credentialIdentifier }))
				.body,
			dpop: ownerTokens.dpop,
		});
		expect(own.status).toBe(200);
	});

	it("binds a deferred transaction to the user it was issued for", async () => {
		const owner = await issuer.signInWithTestUser();
		const other = await signUpAnotherUser();
		const clientId = await issuer.createWalletClient(owner.headers, {
			pairwise: true,
		});
		const ownerTokens = await walletTokens(
			owner.headers,
			clientId,
			DEFERRED_CONFIG_ID,
		);
		const otherTokens = await walletTokens(
			other.headers,
			clientId,
			DEFERRED_CONFIG_ID,
		);
		const { body, jwk } = await proofBody({
			credential_configuration_id: DEFERRED_CONFIG_ID,
		});
		const deferred = await issuer.requestCredential({
			accessToken: ownerTokens.tokens.access_token,
			body,
			dpop: ownerTokens.dpop,
		});
		expect(deferred.status).toBe(202);
		const { transaction_id } = (await deferred.json()) as {
			transaction_id: string;
		};

		const stolen = await issuer.requestCredential({
			accessToken: otherTokens.tokens.access_token,
			url: DEFERRED_URL,
			body: { transaction_id },
			dpop: otherTokens.dpop,
		});
		expect(stolen.status).toBe(400);
		expect((await stolen.json()).error).toBe("invalid_transaction_id");

		const issued = await issuer.requestCredential({
			accessToken: ownerTokens.tokens.access_token,
			url: DEFERRED_URL,
			body: { transaction_id },
			dpop: ownerTokens.dpop,
		});
		expect(issued.status).toBe(200);
		const payload = decodeJwt(
			readCredential(await issued.json()).split("~")[0]!,
		);
		expect(payload).not.toHaveProperty("sub");
		expect(payload.cnf).toEqual({ jwk });
	});

	it("refuses a token whose client was disabled", async () => {
		const { headers } = await issuer.signInWithTestUser();
		const clientId = await issuer.createWalletClient(headers, {
			pairwise: true,
		});
		const { dpop, tokens } = await walletTokens(headers, clientId);
		const { adapter } = await issuer.auth.$context;
		await adapter.update({
			model: "oauthClient",
			where: [{ field: "clientId", value: clientId }],
			update: { disabled: true },
		});

		const res = await issuer.requestCredential({
			accessToken: tokens.access_token,
			body: (await proofBody({ credential_configuration_id: CONFIG_ID })).body,
			dpop,
		});
		expect(res.status).toBe(401);
		expect((await res.json()).error).toBe("invalid_token");
		expect(res.headers.get("www-authenticate")).toMatch(/^DPoP /);
	});

	it("refuses a token whose ba_sub does not decrypt", async () => {
		const { headers, user } = await issuer.signInWithTestUser();
		const clientId = await issuer.createWalletClient(headers, {
			pairwise: true,
		});
		const tokens = await issuer.redeemTokens({
			code: (
				await issuer.createOffer(headers, {
					client_id: clientId,
					credential_configuration_id: CONFIG_ID,
				})
			).code,
			clientId,
		});
		// The claim has its own key, so the Better Auth secret cannot open it.
		const ba_sub = await symmetricEncrypt({
			key: (await issuer.auth.$context).secretConfig,
			data: JSON.stringify({ sub: user.id }),
		});
		const { token } = await issuer.auth.api.signJWT({
			body: {
				payload: { ...decodeJwt(tokens.access_token), ba_sub },
			},
		});

		const res = await issuer.requestCredential({
			accessToken: token,
			body: (await proofBody({ credential_configuration_id: CONFIG_ID })).body,
		});
		expect(res.status).toBe(401);
		expect((await res.json()).error).toBe("invalid_token");
	});

	it("refuses a token that names no user", async () => {
		const { headers } = await issuer.signInWithTestUser();
		const clientId = await issuer.createWalletClient(headers);
		const now = Math.floor(Date.now() / 1000);
		const { token: withoutSub } = await issuer.auth.api.signJWT({
			body: {
				payload: {
					iss: "http://localhost:3000",
					aud: CREDENTIAL_URL,
					azp: clientId,
					iat: now,
					exp: now + 300,
					credential_configuration_id: CONFIG_ID,
				},
			},
		});
		const { token: clientSub } = await issuer.auth.api.signJWT({
			body: {
				payload: {
					iss: "http://localhost:3000",
					sub: clientId,
					aud: CREDENTIAL_URL,
					azp: clientId,
					iat: now,
					exp: now + 300,
					credential_configuration_id: CONFIG_ID,
				},
			},
		});

		for (const accessToken of [withoutSub, clientSub]) {
			const res = await issuer.requestCredential({
				accessToken,
				body: (await proofBody({ credential_configuration_id: CONFIG_ID }))
					.body,
			});
			expect(res.status).toBe(401);
			expect(await res.json()).toMatchObject({
				error: "invalid_token",
				error_description: "access token does not name a user",
			});
		}
	});

	it("answers a missing access token with the provider's challenge", async () => {
		const res = await issuer.customFetchImpl(CREDENTIAL_URL, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ credential_configuration_id: CONFIG_ID }),
		});
		expect(res.status).toBe(401);
		expect((await res.json()).error).toBe("invalid_request");
		expect(res.headers.get("www-authenticate")).toContain("resource_metadata");
	});
});
