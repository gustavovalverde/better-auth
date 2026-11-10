import type { JWK } from "jose";
import { exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import type { HaipOptions } from "../src";
import {
	WALLET_ATTESTATION_AUTH_METHOD,
	WALLET_ATTESTATION_TYPE,
} from "../src";
import {
	AUTH_BASE_URL,
	BASE_URL,
	createHaipServer,
	PRE_AUTH,
	TOKEN_URL,
} from "./haip-server";
import {
	caCert,
	leafCert,
	leafKey,
	rogueCert,
	rogueKey,
	rogueLeafCert,
	rogueLeafKey,
} from "./x509-fixtures";

const PROVIDER = "https://wallet-provider.example";

type Signer = {
	key: CryptoKey | Uint8Array;
	header: Record<string, unknown>;
};

async function createAttestation(input: {
	signer: Signer;
	clientId: string;
	instanceJwk: JWK;
	iss?: string;
	exp?: number | string;
}) {
	return new SignJWT({
		sub: input.clientId,
		cnf: { jwk: input.instanceJwk },
		...(input.iss ? { iss: input.iss } : {}),
	})
		.setProtectedHeader({
			alg: "ES256",
			typ: "oauth-client-attestation+jwt",
			...input.signer.header,
		})
		.setIssuedAt()
		.setExpirationTime(input.exp ?? "1h")
		.sign(input.signer.key);
}

async function createPop(input: {
	instanceKey: CryptoKey;
	aud?: string;
	jti?: string;
	iat?: number;
	challenge?: string;
}) {
	return new SignJWT({
		jti: input.jti ?? crypto.randomUUID(),
		...(input.challenge ? { challenge: input.challenge } : {}),
	})
		.setProtectedHeader({
			alg: "ES256",
			typ: "oauth-client-attestation-pop+jwt",
		})
		.setAudience(input.aud ?? BASE_URL)
		.setIssuedAt(input.iat ?? Math.floor(Date.now() / 1000))
		.sign(input.instanceKey);
}

async function setup(
	haipOptions?: Partial<NonNullable<HaipOptions["walletAttestation"]>>,
) {
	const provider = await generateKeyPair("ES256");
	const providerJwk = {
		...(await exportJWK(provider.publicKey)),
		kid: "provider-1",
	};
	const server = await createHaipServer({
		haip: {
			walletAttestation: {
				trustedIssuers: [
					{ issuer: PROVIDER, jwks: { keys: [providerJwk] } },
					{ trustAnchors: [caCert] },
				],
				...haipOptions,
			},
		},
	});
	const { headers } = await server.signInWithTestUser();
	const instance = await generateKeyPair("ES256");
	const instanceJwk = await exportJWK(instance.publicKey);
	const providerSigner: Signer = {
		key: provider.privateKey,
		header: { kid: "provider-1" },
	};
	const x5cSigner: Signer = {
		key: await importJWK(leafKey as JWK, "ES256"),
		header: { x5c: [leafCert] },
	};

	async function createWallet() {
		const client = await server.createClient(headers, {
			token_endpoint_auth_method: WALLET_ATTESTATION_AUTH_METHOD as never,
			grant_types: [PRE_AUTH],
		});
		return client.client_id;
	}

	async function redeem(clientId: string, clientAssertion: string) {
		const code = await server.createOffer(headers, clientId);
		return server.postForm(TOKEN_URL, {
			grant_type: PRE_AUTH,
			"pre-authorized_code": code,
			client_id: clientId,
			client_assertion_type: WALLET_ATTESTATION_TYPE,
			client_assertion: clientAssertion,
		});
	}

	async function authenticate(
		clientId: string,
		attestation: string,
		pop?: Parameters<typeof createPop>[0],
	) {
		const popJwt = await createPop({
			instanceKey: instance.privateKey,
			...pop,
		});
		return redeem(clientId, `${attestation}~${popJwt}`);
	}

	return {
		server,
		instance,
		instanceJwk,
		providerSigner,
		x5cSigner,
		createWallet,
		redeem,
		authenticate,
	};
}

async function expectInvalidClient(res: Response, reason: string) {
	expect(res.status).toBe(400);
	const body = (await res.json()) as {
		error?: string;
		error_description?: string;
	};
	expect(body.error).toBe("invalid_client");
	expect(body.error_description).toContain(reason);
}

describe("haip - attestation-based client authentication", async () => {
	const ctx = await setup();

	it("authenticates a wallet attested by a configured JWKS", async () => {
		const clientId = await ctx.createWallet();
		const attestation = await createAttestation({
			signer: ctx.providerSigner,
			clientId,
			instanceJwk: ctx.instanceJwk,
			iss: PROVIDER,
		});
		const res = await ctx.authenticate(clientId, attestation);
		expect(res.status).toBe(200);
	});

	it("authenticates a wallet attested through an x5c chain to a trust anchor", async () => {
		const clientId = await ctx.createWallet();
		const attestation = await createAttestation({
			signer: ctx.x5cSigner,
			clientId,
			instanceJwk: ctx.instanceJwk,
		});
		expect((await ctx.authenticate(clientId, attestation)).status).toBe(200);
	});

	it("rejects a self-signed attestation that names a trusted issuer in iss", async () => {
		const clientId = await ctx.createWallet();
		const forger = await generateKeyPair("ES256");
		const attestation = await createAttestation({
			signer: {
				key: forger.privateKey,
				header: { jwk: await exportJWK(forger.publicKey) },
			},
			clientId,
			instanceJwk: ctx.instanceJwk,
			iss: PROVIDER,
		});
		await expectInvalidClient(
			await ctx.authenticate(clientId, attestation),
			"not trusted",
		);
	});

	it("rejects an attestation signed by an unconfigured key with a trusted iss and kid", async () => {
		const clientId = await ctx.createWallet();
		const forger = await generateKeyPair("ES256");
		const attestation = await createAttestation({
			signer: { key: forger.privateKey, header: { kid: "provider-1" } },
			clientId,
			instanceJwk: ctx.instanceJwk,
			iss: PROVIDER,
		});
		await expectInvalidClient(
			await ctx.authenticate(clientId, attestation),
			"not signed by a trusted issuer",
		);
	});

	it("rejects a self-signed x5c certificate", async () => {
		const clientId = await ctx.createWallet();
		const attestation = await createAttestation({
			signer: {
				key: await importJWK(rogueKey as JWK, "ES256"),
				header: { x5c: [rogueCert] },
			},
			clientId,
			instanceJwk: ctx.instanceJwk,
		});
		await expectInvalidClient(
			await ctx.authenticate(clientId, attestation),
			"x5c chain",
		);
	});

	it("rejects an x5c chain whose root impersonates the trust anchor's name", async () => {
		const clientId = await ctx.createWallet();
		const attestation = await createAttestation({
			signer: {
				key: await importJWK(rogueLeafKey as JWK, "ES256"),
				header: { x5c: [rogueLeafCert, rogueCert] },
			},
			clientId,
			instanceJwk: ctx.instanceJwk,
		});
		await expectInvalidClient(
			await ctx.authenticate(clientId, attestation),
			"x5c chain",
		);
	});

	it("rejects an attestation issued for another client", async () => {
		const clientId = await ctx.createWallet();
		const attestation = await createAttestation({
			signer: ctx.providerSigner,
			clientId: "another-client",
			instanceJwk: ctx.instanceJwk,
			iss: PROVIDER,
		});
		await expectInvalidClient(
			await ctx.authenticate(clientId, attestation),
			"sub does not match",
		);
	});

	it("rejects an expired attestation", async () => {
		const clientId = await ctx.createWallet();
		const attestation = await createAttestation({
			signer: ctx.providerSigner,
			clientId,
			instanceJwk: ctx.instanceJwk,
			iss: PROVIDER,
			exp: Math.floor(Date.now() / 1000) - 60,
		});
		await expectInvalidClient(
			await ctx.authenticate(clientId, attestation),
			"exp",
		);
	});

	it("rejects a PoP signed by a key other than cnf.jwk", async () => {
		const clientId = await ctx.createWallet();
		const attestation = await createAttestation({
			signer: ctx.providerSigner,
			clientId,
			instanceJwk: ctx.instanceJwk,
			iss: PROVIDER,
		});
		const other = await generateKeyPair("ES256");
		const pop = await createPop({ instanceKey: other.privateKey });
		await expectInvalidClient(
			await ctx.redeem(clientId, `${attestation}~${pop}`),
			"PoP",
		);
	});

	it("rejects a PoP for another audience", async () => {
		const clientId = await ctx.createWallet();
		const attestation = await createAttestation({
			signer: ctx.providerSigner,
			clientId,
			instanceJwk: ctx.instanceJwk,
			iss: PROVIDER,
		});
		await expectInvalidClient(
			await ctx.authenticate(clientId, attestation, {
				instanceKey: ctx.instance.privateKey,
				aud: "https://other-as.example",
			}),
			"aud",
		);
	});

	it("rejects a stale PoP", async () => {
		const clientId = await ctx.createWallet();
		const attestation = await createAttestation({
			signer: ctx.providerSigner,
			clientId,
			instanceJwk: ctx.instanceJwk,
			iss: PROVIDER,
		});
		await expectInvalidClient(
			await ctx.authenticate(clientId, attestation, {
				instanceKey: ctx.instance.privateKey,
				iat: Math.floor(Date.now() / 1000) - 3600,
			}),
			"too old",
		);
	});

	it("rejects a replayed PoP jti", async () => {
		const clientId = await ctx.createWallet();
		const attestation = await createAttestation({
			signer: ctx.providerSigner,
			clientId,
			instanceJwk: ctx.instanceJwk,
			iss: PROVIDER,
		});
		const pop = {
			instanceKey: ctx.instance.privateKey,
			jti: crypto.randomUUID(),
		};
		expect((await ctx.authenticate(clientId, attestation, pop)).status).toBe(
			200,
		);
		const replay = await ctx.authenticate(clientId, attestation, pop);
		expect(replay.status).toBe(400);
		expect((await replay.json()).error).toBe("invalid_client");
	});

	it("advertises attest_jwt_client_auth and the challenge endpoint", async () => {
		const metadata =
			(await ctx.server.auth.api.getOAuthServerConfig()) as Record<
				string,
				unknown
			>;
		expect(metadata.token_endpoint_auth_methods_supported).toContain(
			WALLET_ATTESTATION_AUTH_METHOD,
		);
		expect(metadata.challenge_endpoint).toBe(
			`${AUTH_BASE_URL}/oauth2/attestation-challenge`,
		);
		expect(
			metadata.client_attestation_pop_signing_alg_values_supported,
		).toEqual(["ES256"]);
	});
});

describe("haip - attestation challenges", async () => {
	const ctx = await setup({ requireChallenge: true });

	async function challenge() {
		const res = await ctx.server.customFetchImpl(
			`${AUTH_BASE_URL}/oauth2/attestation-challenge`,
			{ method: "POST" },
		);
		expect(res.headers.get("cache-control")).toContain("no-store");
		return ((await res.json()) as { attestation_challenge: string })
			.attestation_challenge;
	}

	it("requires a challenge, accepts an issued one once, and rejects others", async () => {
		const clientId = await ctx.createWallet();
		const attestation = await createAttestation({
			signer: ctx.providerSigner,
			clientId,
			instanceJwk: ctx.instanceJwk,
			iss: PROVIDER,
		});

		const missing = await ctx.authenticate(clientId, attestation);
		expect((await missing.json()).error).toBe("use_attestation_challenge");

		const issued = await challenge();
		const ok = await ctx.authenticate(clientId, attestation, {
			instanceKey: ctx.instance.privateKey,
			challenge: issued,
		});
		expect(ok.status).toBe(200);

		const reused = await ctx.authenticate(clientId, attestation, {
			instanceKey: ctx.instance.privateKey,
			challenge: issued,
		});
		expect((await reused.json()).error).toBe("use_attestation_challenge");

		const unknown = await ctx.authenticate(clientId, attestation, {
			instanceKey: ctx.instance.privateKey,
			challenge: "never-issued",
		});
		expect((await unknown.json()).error).toBe("use_attestation_challenge");
	});
});
