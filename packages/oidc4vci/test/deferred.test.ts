import { describe, expect, it } from "vitest";
import {
	CONFIG_ID,
	createIssuer,
	createJwtProof,
	DEFERRED_URL,
	readCredential,
} from "./issuer";

describe("oidc4vci - deferred issuance", async () => {
	let ready = false;
	const issuer = await createIssuer({
		oidc4vci: {
			deferredIssuance: {
				shouldDefer: () => true,
				isReady: () => ready,
				intervalSeconds: 5,
			},
		},
	});

	it("advertises the deferred credential endpoint", async () => {
		const metadata = (await issuer.auth.api.getCredentialIssuerMetadata()) as {
			deferred_credential_endpoint?: string;
		};
		expect(metadata.deferred_credential_endpoint).toBe(DEFERRED_URL);
	});

	it("answers 202 until ready, then issues once per transaction_id", async () => {
		const { tokens } = await issuer.issueAccessToken();
		const { proofJwt, jwk } = await createJwtProof({
			nonce: await issuer.nonce(),
		});
		const deferred = await issuer.requestCredential({
			accessToken: tokens.access_token,
			body: {
				credential_configuration_id: CONFIG_ID,
				proofs: { jwt: [proofJwt] },
			},
		});
		expect(deferred.status).toBe(202);
		const { transaction_id, interval } = (await deferred.json()) as {
			transaction_id: string;
			interval: number;
		};
		expect(transaction_id).toBeTypeOf("string");
		expect(interval).toBe(5);

		ready = false;
		const pending = await issuer.requestCredential({
			accessToken: tokens.access_token,
			url: DEFERRED_URL,
			body: { transaction_id },
		});
		expect(pending.status).toBe(202);
		expect(await pending.json()).toEqual({ transaction_id, interval: 5 });

		ready = true;
		const issued = await issuer.requestCredential({
			accessToken: tokens.access_token,
			url: DEFERRED_URL,
			body: { transaction_id },
		});
		expect(issued.status).toBe(200);
		const credential = readCredential(await issued.json());
		const payload = JSON.parse(
			Buffer.from(credential.split(".")[1]!, "base64url").toString(),
		) as { cnf?: unknown };
		expect(payload.cnf).toEqual({ jwk });

		const again = await issuer.requestCredential({
			accessToken: tokens.access_token,
			url: DEFERRED_URL,
			body: { transaction_id },
		});
		expect(again.status).toBe(400);
		expect((await again.json()).error).toBe("invalid_transaction_id");
	});
});
