import { describe, expect, it } from "vitest";
import {
	createDpopKey,
	createFpaServer,
	TEST_EMAIL,
	TEST_PASSWORD,
} from "./fpa-server";

describe("first-party apps - password flow", async () => {
	const server = await createFpaServer();

	it("signs in with a hint, a password, and a code redeemed without redirect_uri", async () => {
		const client = await server.createClient();
		const dpop = await createDpopKey();
		const { res, pkce } = await server.startPassword(client.client_id, {
			dpop,
		});
		expect(res.status).toBe(403);
		expect(res.headers.get("cache-control")).toBe("no-store");
		expect(res.body).toEqual({
			error: "insufficient_authorization",
			auth_session: expect.any(String),
			challenge_type: "password",
		});

		const final = await server.challenge(
			{ auth_session: res.body.auth_session, password: TEST_PASSWORD },
			{ dpop },
		);
		expect(final.status).toBe(200);
		expect(final.headers.get("cache-control")).toBe("no-store");
		expect(final.body).toEqual({ authorization_code: expect.any(String) });

		const tokens = await server.redeem(
			client.client_id,
			final.body.authorization_code,
			pkce.verifier,
			{ dpop },
		);
		expect(tokens.status).toBe(200);
		expect(tokens.body.token_type).toBe("DPoP");
		expect(tokens.body.refresh_token).toEqual(expect.any(String));
		expect(server.decodeJwt(tokens.body.id_token).sub).toEqual(
			expect.any(String),
		);
	});

	it("rejects a token request that repeats a redirect_uri", async () => {
		const client = await server.createClient();
		const { final, pkce } = await server.signIn(client.client_id);
		const tokens = await server.redeem(
			client.client_id,
			final.body.authorization_code,
			pkce.verifier,
			{ extra: { redirect_uri: "https://app.example/callback" } },
		);
		expect(tokens.status).toBe(400);
		expect(tokens.body.error).toBe("invalid_grant");
	});

	it("gives an unknown email the same challenge as a known one", async () => {
		const client = await server.createClient();
		const known = await server.startPassword(client.client_id);
		const unknown = await server.startPassword(client.client_id, {
			extra: { login_hint: "nobody@example.com" },
		});
		expect(unknown.res.status).toBe(known.res.status);
		expect(Object.keys(unknown.res.body).sort()).toEqual(
			Object.keys(known.res.body).sort(),
		);
		const failed = await server.challenge({
			auth_session: unknown.res.body.auth_session,
			password: TEST_PASSWORD,
		});
		expect(failed.status).toBe(400);
		expect(failed.body.error).toBe("authentication_failed");
	});

	it("answers a wrong password with authentication_failed and a fresh challenge", async () => {
		const client = await server.createClient();
		const { res } = await server.startPassword(client.client_id);
		const failed = await server.challenge({
			auth_session: res.body.auth_session,
			password: "wrong-password",
		});
		expect(failed.status).toBe(400);
		expect(failed.body).toEqual({
			error: "authentication_failed",
			error_description: expect.any(String),
			auth_session: res.body.auth_session,
			challenge_type: "password",
		});
		const retried = await server.challenge({
			auth_session: res.body.auth_session,
			password: TEST_PASSWORD,
		});
		expect(retried.status).toBe(200);
	});

	it("ends the flow with redirect_to_web on the third failure", async () => {
		const client = await server.createClient();
		const { res } = await server.startPassword(client.client_id);
		const handle = res.body.auth_session;
		for (let attempt = 0; attempt < 2; attempt++) {
			const failed = await server.challenge({
				auth_session: handle,
				password: "wrong-password",
			});
			expect(failed.body.error).toBe("authentication_failed");
		}
		const third = await server.challenge({
			auth_session: handle,
			password: "wrong-password",
		});
		expect(third.status).toBe(403);
		expect(third.body.error).toBe("redirect_to_web");
		expect(third.body.auth_session).toBeUndefined();
		const after = await server.challenge({
			auth_session: handle,
			password: TEST_PASSWORD,
		});
		expect(after.body.error).toBe("invalid_session");
	});
});

describe("first-party apps - email verification", async () => {
	const server = await createFpaServer({
		auth: {
			emailAndPassword: { enabled: true, requireEmailVerification: true },
		},
	});
	const email = "unverified@example.com";
	await server.auth.api.signUpEmail!({
		body: { email, password: TEST_PASSWORD, name: "Unverified" },
	});

	it("answers redirect_to_web after a correct password for an unverified email", async () => {
		const client = await server.createClient();
		const extra = { login_hint: email };
		const { res } = await server.startPassword(client.client_id, { extra });
		const final = await server.challenge({
			auth_session: res.body.auth_session,
			password: TEST_PASSWORD,
		});
		expect(final.status).toBe(403);
		expect(final.body.error).toBe("redirect_to_web");

		const wrong = await server.startPassword(client.client_id, { extra });
		const failed = await server.challenge({
			auth_session: wrong.res.body.auth_session,
			password: "wrong-password",
		});
		expect(failed.body.error).toBe("authentication_failed");
	});

	it("signs in a verified user", async () => {
		const client = await server.createClient();
		const { final } = await server.signIn(client.client_id);
		expect(final.body.authorization_code).toEqual(expect.any(String));
		expect(TEST_EMAIL).toBe("test@test.com");
	});
});
