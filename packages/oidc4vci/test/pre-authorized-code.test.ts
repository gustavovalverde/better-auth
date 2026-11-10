import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import {
	CONFIG_ID,
	CREDENTIAL_URL,
	createDpopKey,
	createIssuer,
	createJwtProof,
	readCredential,
} from "./issuer";

describe("oidc4vci - pre-authorized code grant", async () => {
	const issuer = await createIssuer();

	it("issues tokens without c_nonce and a credential with a Nonce Endpoint nonce", async () => {
		const { headers, user } = await issuer.signInWithTestUser();
		const clientId = await issuer.createWalletClient(headers);
		const { code } = await issuer.createOffer(headers, {
			client_id: clientId,
			credential_configuration_id: CONFIG_ID,
		});

		const tokens = await issuer.redeemTokens({ code, clientId });
		expect(tokens.access_token).toBeTypeOf("string");
		expect(tokens).not.toHaveProperty("c_nonce");
		expect(tokens).not.toHaveProperty("c_nonce_expires_in");
		expect(
			tokens.authorization_details?.[0]?.credential_identifiers?.[0],
		).toBeTypeOf("string");
		expect(decodeJwt(tokens.access_token).aud).toContain(CREDENTIAL_URL);

		const { proofJwt } = await createJwtProof({ nonce: await issuer.nonce() });
		const res = await issuer.requestCredential({
			accessToken: tokens.access_token,
			body: {
				credential_configuration_id: CONFIG_ID,
				proofs: { jwt: [proofJwt] },
			},
		});
		expect(res.status).toBe(200);
		const body = await res.json();
		expect(body).not.toHaveProperty("c_nonce");
		const credential = readCredential(body);
		expect(decodeJwt(credential.split("~")[0]!).sub).toBe(user.id);
	});

	it("redeems a pre-authorized code once under concurrent requests", async () => {
		const { headers } = await issuer.signInWithTestUser();
		const clientId = await issuer.createWalletClient(headers);
		const { code } = await issuer.createOffer(headers, {
			client_id: clientId,
			credential_configuration_id: CONFIG_ID,
		});

		const results = await Promise.all(
			Array.from({ length: 4 }, () => issuer.redeem({ code, clientId })),
		);
		const statuses = results.map((res) => res.status);
		expect(statuses.filter((status) => status === 200)).toHaveLength(1);
		expect(statuses.filter((status) => status === 400)).toHaveLength(3);
	});

	it("requires the tx_code and keeps the code for a corrected retry", async () => {
		const { headers } = await issuer.signInWithTestUser();
		const clientId = await issuer.createWalletClient(headers);
		const { code, offer } = await issuer.createOffer(headers, {
			client_id: clientId,
			credential_configuration_id: CONFIG_ID,
			tx_code: "493536",
		});
		expect(
			offer.credential_offer.grants[
				"urn:ietf:params:oauth:grant-type:pre-authorized_code"
			].tx_code,
		).toEqual({ input_mode: "numeric", length: 6 });

		const missing = await issuer.redeem({ code, clientId });
		expect(missing.status).toBe(400);
		expect((await missing.json()).error).toBe("invalid_grant");
		const wrong = await issuer.redeem({ code, clientId, txCode: "000000" });
		expect(wrong.status).toBe(400);

		const ok = await issuer.redeem({ code, clientId, txCode: "493536" });
		expect(ok.status).toBe(200);
	});

	it("rejects a code presented by another client", async () => {
		const { headers } = await issuer.signInWithTestUser();
		const clientId = await issuer.createWalletClient(headers);
		const otherClientId = await issuer.createWalletClient(headers);
		const { code } = await issuer.createOffer(headers, {
			client_id: clientId,
			credential_configuration_id: CONFIG_ID,
		});

		const res = await issuer.redeem({ code, clientId: otherClientId });
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("invalid_grant");
		expect((await issuer.redeem({ code, clientId })).status).toBe(200);
	});

	it("rejects a resource other than the credential endpoint", async () => {
		const { headers } = await issuer.signInWithTestUser();
		const clientId = await issuer.createWalletClient(headers);
		const { code } = await issuer.createOffer(headers, {
			client_id: clientId,
			credential_configuration_id: CONFIG_ID,
		});

		const res = await issuer.redeem({
			code,
			clientId,
			resource: "http://localhost:3000/api/auth",
		});
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("invalid_target");
	});

	it("binds the token to the DPoP key presented at the token endpoint", async () => {
		const { headers } = await issuer.signInWithTestUser();
		const clientId = await issuer.createWalletClient(headers);
		const { code } = await issuer.createOffer(headers, {
			client_id: clientId,
			credential_configuration_id: CONFIG_ID,
		});
		const dpop = await createDpopKey();

		const tokens = await issuer.redeemTokens({ code, clientId, dpop });
		expect(tokens.token_type).toBe("DPoP");
		expect(decodeJwt(tokens.access_token).cnf).toEqual({ jkt: dpop.jkt });
	});

	it("only lets a user create offers about themselves by default", async () => {
		const victim = await issuer.signInWithTestUser();
		const { headers: attackerHeaders } = await signUpAnotherUser();
		const clientId = await issuer.createWalletClient(victim.headers);

		await expect(
			issuer.auth.api.createCredentialOffer({
				headers: attackerHeaders,
				body: {
					client_id: clientId,
					userId: victim.user.id,
					credential_configuration_id: CONFIG_ID,
				},
			}),
		).rejects.toMatchObject({ status: "FORBIDDEN" });
	});

	async function signUpAnotherUser() {
		const email = `other-${crypto.randomUUID()}@example.com`;
		const password = "password-for-another-user";
		await issuer.auth.api.signUpEmail({
			body: { email, password, name: "Other" },
		});
		return issuer.signInWithUser(email, password);
	}
});

describe("oidc4vci - credential offer authorization", async () => {
	const issuer = await createIssuer({
		oidc4vci: {
			authorizeCredentialOffer: ({ session }) =>
				session.user.email === "test@test.com",
		},
	});

	it("lets authorizeCredentialOffer allow offers about another user", async () => {
		const { headers, user } = await issuer.signInWithTestUser();
		const clientId = await issuer.createWalletClient(headers);
		const { code } = await issuer.createOffer(headers, {
			client_id: clientId,
			userId: user.id,
			credential_configuration_id: CONFIG_ID,
		});
		expect(code).toBeTypeOf("string");
	});
});
