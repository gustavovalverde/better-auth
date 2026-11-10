import type { JWK } from "jose";
import {
	decodeJwt,
	exportJWK,
	generateKeyPair,
	importJWK,
	SignJWT,
} from "jose";
import { describe, expect, it } from "vitest";
import { createKeyAttestationValidator } from "../src";
import { CONFIG_ID, createHaipServer } from "./haip-server";
import {
	caCert,
	leafCert,
	leafKey,
	rogueCert,
	rogueKey,
} from "./x509-fixtures";

async function createKeyAttestation(input: {
	key: CryptoKey | Uint8Array;
	header: Record<string, unknown>;
	attestedKeys: JWK[];
	nonce?: string;
	iat?: number;
}) {
	return new SignJWT({
		attested_keys: input.attestedKeys,
		...(input.nonce ? { nonce: input.nonce } : {}),
		key_storage: ["iso_18045_moderate"],
	})
		.setProtectedHeader({
			alg: "ES256",
			typ: "key-attestation+jwt",
			...input.header,
		})
		.setIssuedAt(input.iat ?? Math.floor(Date.now() / 1000))
		.setExpirationTime("1h")
		.sign(input.key);
}

describe("haip - key attestation proofs", async () => {
	const validate = createKeyAttestationValidator({
		trustedIssuers: [{ trustAnchors: [caCert] }],
	});
	const holder = await generateKeyPair("ES256");
	const holderJwk = await exportJWK(holder.publicKey);
	const trustedKey = await importJWK(leafKey as JWK, "ES256");
	const input = (proof: string) => ({
		proof,
		proofType: "attestation",
		audience: "http://localhost:3000",
	});

	it("returns the attested key and nonce of a trusted attestation", async () => {
		const proof = await createKeyAttestation({
			key: trustedKey,
			header: { x5c: [leafCert] },
			attestedKeys: [holderJwk],
			nonce: "c-nonce",
		});
		await expect(validate(input(proof))).resolves.toEqual({
			jwk: holderJwk,
			cNonce: "c-nonce",
		});
	});

	it("rejects an attestation verified only by its own header jwk", async () => {
		const forger = await generateKeyPair("ES256");
		const proof = await createKeyAttestation({
			key: forger.privateKey,
			header: { jwk: await exportJWK(forger.publicKey) },
			attestedKeys: [holderJwk],
			nonce: "c-nonce",
		});
		await expect(validate(input(proof))).rejects.toThrow("not trusted");
	});

	it("rejects a self-signed x5c certificate", async () => {
		const proof = await createKeyAttestation({
			key: await importJWK(rogueKey as JWK, "ES256"),
			header: { x5c: [rogueCert] },
			attestedKeys: [holderJwk],
			nonce: "c-nonce",
		});
		await expect(validate(input(proof))).rejects.toThrow("x5c chain");
	});

	it.each([
		["without a nonce", { nonce: undefined }, "c_nonce"],
		["with several attested keys", { attestedKeys: "two" }, "exactly one key"],
		["that is stale", { iat: Math.floor(Date.now() / 1000) - 3600 }, "iat"],
	])("rejects an attestation %s", async (_label, overrides, reason) => {
		const other = await exportJWK((await generateKeyPair("ES256")).publicKey);
		const proof = await createKeyAttestation({
			key: trustedKey,
			header: { x5c: [leafCert] },
			attestedKeys:
				(overrides as { attestedKeys?: string }).attestedKeys === "two"
					? [holderJwk, other]
					: [holderJwk],
			nonce: "nonce" in overrides ? overrides.nonce : "c-nonce",
			iat: (overrides as { iat?: number }).iat,
		});
		await expect(validate(input(proof))).rejects.toThrow(reason);
	});
});

describe("haip - attestation proof at the credential endpoint", async () => {
	const server = await createHaipServer({
		oidc4vci: {
			proofValidators: {
				attestation: createKeyAttestationValidator({
					trustedIssuers: [{ trustAnchors: [caCert] }],
				}),
			},
		},
	});

	it("binds the credential to the attested key", async () => {
		const holder = await generateKeyPair("ES256");
		const holderJwk = await exportJWK(holder.publicKey);
		const { accessToken, dpop } = await server.issueAccessToken();
		const proof = await createKeyAttestation({
			key: await importJWK(leafKey as JWK, "ES256"),
			header: { x5c: [leafCert, caCert] },
			attestedKeys: [holderJwk],
			nonce: await server.nonce(),
		});
		const res = await server.requestCredential({
			accessToken,
			dpop,
			body: {
				credential_configuration_id: CONFIG_ID,
				proofs: { attestation: [proof] },
			},
		});
		expect(res.status).toBe(200);
		const body = (await res.json()) as {
			credentials: Array<{ credential: string }>;
		};
		const payload = decodeJwt(body.credentials[0]!.credential.split("~")[0]!);
		expect(payload.cnf).toEqual({ jwk: holderJwk });
	});

	it("rejects a forged attestation with invalid_proof", async () => {
		const forger = await generateKeyPair("ES256");
		const { accessToken, dpop } = await server.issueAccessToken();
		const proof = await createKeyAttestation({
			key: forger.privateKey,
			header: { jwk: await exportJWK(forger.publicKey) },
			attestedKeys: [await exportJWK(forger.publicKey)],
			nonce: await server.nonce(),
		});
		const res = await server.requestCredential({
			accessToken,
			dpop,
			body: {
				credential_configuration_id: CONFIG_ID,
				proofs: { attestation: [proof] },
			},
		});
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("invalid_proof");
	});
});
