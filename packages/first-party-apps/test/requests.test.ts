import { describe, expect, it } from "vitest";
import { createFpaServer, TEST_EMAIL, TEST_PASSWORD } from "./fpa-server";

const BASE = {
	response_type: "code",
	scope: "openid",
	login_hint: TEST_EMAIL,
};

describe("first-party apps - encoding", async () => {
	const server = await createFpaServer();
	const client = await server.createClient();

	it("requires form encoding on the initial request", async () => {
		const json = await server.challenge(
			{ ...BASE, client_id: client.client_id },
			{ json: true },
		);
		expect(json.status).toBe(400);
		expect(json.body.error).toBe("invalid_request");

		const form = await server.challenge({
			...BASE,
			client_id: client.client_id,
		});
		expect(form.status).toBe(403);
		expect(form.body.error).toBe("insufficient_authorization");
	});

	it("accepts a JSON follow-up", async () => {
		const { res } = await server.startPassword(client.client_id);
		const final = await server.challenge(
			{ auth_session: res.body.auth_session, password: TEST_PASSWORD },
			{ json: true },
		);
		expect(final.status).toBe(200);
		expect(final.body.authorization_code).toEqual(expect.any(String));
	});

	it("rejects a repeated parameter and accepts a repeated resource", async () => {
		const repeated = await server.challenge({
			...BASE,
			client_id: client.client_id,
			scope: ["openid", "profile"],
		});
		expect(repeated.status).toBe(400);
		expect(repeated.body.error).toBe("invalid_request");

		const resources = await server.challenge({
			...BASE,
			client_id: client.client_id,
			resource: ["https://api.example/a", "https://api.example/b"],
		});
		expect(resources.status).toBe(403);
		expect(resources.body.error).toBe("insufficient_authorization");
	});

	it("marks every response no-store, including a schema error", async () => {
		const schemaError = await server.challenge({
			...BASE,
			client_id: client.client_id,
			max_age: "soon",
		});
		expect(schemaError.status).toBe(400);
		expect(schemaError.body.error).toBe("invalid_request");
		expect(schemaError.headers.get("cache-control")).toBe("no-store");

		const unknownSession = await server.challenge({ auth_session: "nope" });
		expect(unknownSession.status).toBe(400);
		expect(unknownSession.body.error).toBe("invalid_session");
		expect(unknownSession.headers.get("cache-control")).toBe("no-store");
	});
});

describe("first-party apps - initial request", async () => {
	const server = await createFpaServer();
	const client = await server.createClient();
	const send = (params: Record<string, string>) =>
		server.challenge({ ...BASE, client_id: client.client_id, ...params });

	it("requires response_type=code", async () => {
		const { response_type: _, ...withoutType } = BASE;
		const missing = await server.challenge({
			...withoutType,
			client_id: client.client_id,
		});
		expect(missing.body.error).toBe("invalid_request");

		const token = await send({ response_type: "token" });
		expect(token.status).toBe(400);
		expect(token.body.error).toBe("unsupported_response_type");
	});

	it("rejects request_uri and request with the provider's codes", async () => {
		const requestUri = await send({ request_uri: "urn:example:request" });
		expect(requestUri.body.error).toBe("invalid_request");
		const request = await send({ request: "eyJhbGciOiJub25lIn0.e30." });
		expect(request.body.error).toBe("request_not_supported");
	});

	it("rejects a redirect_uri, because a challenge code is never bound to one", async () => {
		const res = await send({ redirect_uri: "https://app.example/callback" });
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_request");
	});

	it("rejects a credential before any challenge", async () => {
		const res = await send({ password: TEST_PASSWORD });
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_request");
	});

	it("answers prompt=none with login_required and prompt=consent with redirect_to_web", async () => {
		const none = await send({ prompt: "none" });
		expect(none.status).toBe(400);
		expect(none.body.error).toBe("login_required");
		const consent = await send({ prompt: "consent" });
		expect(consent.status).toBe(403);
		expect(consent.body.error).toBe("redirect_to_web");
	});

	it("answers redirect_to_web when no method handles the hint", async () => {
		const before = (await server.authSessionRows()).length;
		const res = await send({ login_hint: "not-an-email" });
		expect(res.status).toBe(403);
		expect(res.body.error).toBe("redirect_to_web");
		expect(res.body.auth_session).toBeUndefined();
		expect((await server.authSessionRows()).length).toBe(before);
	});

	it("drops plugin-owned fields from a method's challenge", async () => {
		const { res } = await server.startOtp(client.client_id);
		expect(res.body).toEqual({
			error: "insufficient_authorization",
			auth_session: expect.any(String),
			challenge_type: "otp",
			round: 1,
		});
		expect(res.body.auth_session).not.toBe("x");
	});
});

describe("first-party apps - clients", async () => {
	const server = await createFpaServer();

	it("rejects an unknown client and a confidential client without credentials", async () => {
		const unknown = await server.challenge({ ...BASE, client_id: "unknown" });
		expect(unknown.status).toBe(400);
		expect(unknown.body.error).toBe("invalid_client");

		const confidential = await server.createClient({
			token_endpoint_auth_method: "client_secret_post",
		});
		const missing = await server.challenge({
			...BASE,
			client_id: confidential.client_id,
		});
		expect(missing.body.error).toBe("invalid_client");
	});

	it("never calls start for a confidential client with a wrong secret", async () => {
		const confidential = await server.createClient({
			token_endpoint_auth_method: "client_secret_post",
		});
		const starts = server.recording.calls.start;
		const res = await server.challenge({
			...BASE,
			login_hint: `otp:${TEST_EMAIL}`,
			client_id: confidential.client_id,
			client_secret: "wrong",
		});
		expect(res.body.error).toBe("invalid_client");
		expect(server.recording.calls.start).toBe(starts);
	});

	it("signs in a confidential client that authenticates on every request", async () => {
		const confidential = await server.createClient({
			token_endpoint_auth_method: "client_secret_post",
		});
		const secret = confidential.client_secret!;
		const { res, pkce } = await server.startPassword(confidential.client_id, {
			extra: { client_secret: secret },
		});
		const withoutSecret = await server.challenge({
			auth_session: res.body.auth_session,
			password: "wrong-password",
		});
		expect(withoutSecret.body.error).toBe("invalid_client");

		const final = await server.challenge({
			auth_session: res.body.auth_session,
			password: TEST_PASSWORD,
			client_secret: secret,
		});
		expect(final.status).toBe(200);
		const tokens = await server.redeem(
			confidential.client_id,
			final.body.authorization_code,
			pkce.verifier,
			{ extra: { client_secret: secret } },
		);
		expect(tokens.status).toBe(200);
	});

	it("answers unauthorized_client for a client without the authorization_code grant", async () => {
		const client = await server.createClient({
			grant_types: ["client_credentials"],
			token_endpoint_auth_method: "client_secret_post",
		});
		const res = await server.challenge({
			...BASE,
			client_id: client.client_id,
			client_secret: client.client_secret!,
		});
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("unauthorized_client");
	});

	it("answers unauthorized_client for a client the policy rejects, without a row", async () => {
		const client = await server.createClient({}, { firstParty: false });
		const before = (await server.authSessionRows()).length;
		const res = await server.challenge({
			...BASE,
			client_id: client.client_id,
		});
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("unauthorized_client");
		expect((await server.authSessionRows()).length).toBe(before);
	});

	it("rejects a follow-up that names another client and accepts one that omits client_id", async () => {
		const client = await server.createClient();
		const other = await server.createClient();
		const { res } = await server.startPassword(client.client_id);
		const mismatch = await server.challenge({
			auth_session: res.body.auth_session,
			client_id: other.client_id,
			password: TEST_PASSWORD,
		});
		expect(mismatch.status).toBe(400);
		expect(mismatch.body.error).toBe("invalid_client");

		const omitted = await server.challenge({
			auth_session: res.body.auth_session,
			password: TEST_PASSWORD,
		});
		expect(omitted.status).toBe(200);
	});

	it("stops a flow when the client stops being first-party", async () => {
		const client = await server.createClient();
		const { res } = await server.startPassword(client.client_id);
		server.firstParty.delete(client.client_id);
		const demoted = await server.challenge({
			auth_session: res.body.auth_session,
			password: TEST_PASSWORD,
		});
		expect(demoted.status).toBe(400);
		expect(demoted.body.error).toBe("unauthorized_client");
		expect(await server.findRow(res.body.auth_session)).toBeNull();
	});
});
