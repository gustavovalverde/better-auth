import { describe, expect, it } from "vitest";
import {
	CHALLENGE_URL,
	createDpopKey,
	createDpopProof,
	createFpaServer,
	TEST_PASSWORD,
} from "./fpa-server";

describe("first-party apps - DPoP binding", async () => {
	const server = await createFpaServer();
	const client = await server.createClient();

	it("binds the row to the initial proof's key", async () => {
		const dpop = await createDpopKey();
		const { handle } = await server.startOtp(client.client_id, { dpop });
		expect((await server.findRow(handle))?.dpopJkt).toBe(dpop.jkt);
	});

	it("rejects a follow-up without a proof or with another key before respond runs", async () => {
		const dpop = await createDpopKey();
		const { handle } = await server.startOtp(client.client_id, { dpop });
		const responds = server.recording.calls.respond;

		const missing = await server.challenge({
			auth_session: handle,
			otp_code: "one",
		});
		expect(missing.status).toBe(400);
		expect(missing.body.error).toBe("invalid_dpop_proof");

		const other = await server.challenge(
			{ auth_session: handle, otp_code: "one" },
			{ dpop: await createDpopKey() },
		);
		expect(other.body.error).toBe("invalid_dpop_proof");
		expect(server.recording.calls.respond).toBe(responds);

		const right = await server.challenge(
			{ auth_session: handle, otp_code: "one" },
			{ dpop },
		);
		expect(right.body).toMatchObject({
			error: "insufficient_authorization",
			challenge_type: "otp",
			round: 2,
		});
	});

	it("rejects a proof on a row without a binding", async () => {
		const { handle } = await server.startOtp(client.client_id);
		const res = await server.challenge(
			{ auth_session: handle, otp_code: "one" },
			{ dpop: await createDpopKey() },
		);
		expect(res.body.error).toBe("invalid_dpop_proof");
	});

	it("issues a code with one proof and requires the same key at the token endpoint", async () => {
		const dpop = await createDpopKey();
		const { final, pkce } = await server.signIn(client.client_id, { dpop });
		expect(final.status).toBe(200);
		const otherKey = await server.redeem(
			client.client_id,
			final.body.authorization_code,
			pkce.verifier,
			{ dpop: await createDpopKey() },
		);
		expect(otherKey.status).toBe(400);
		expect(otherKey.body.error).toBe("invalid_dpop_proof");
		const sameKey = await server.redeem(
			client.client_id,
			final.body.authorization_code,
			pkce.verifier,
			{ dpop },
		);
		expect(sameKey.status).toBe(200);
	});

	it("answers a forged proof for the right key the same for right and wrong credentials", async () => {
		const dpop = await createDpopKey();
		const forger = await createDpopKey();
		const forged = () =>
			createDpopProof(dpop, { url: CHALLENGE_URL, signWith: forger });
		const sessionsBefore = (await server.sessionRows()).length;
		const right = await server.startPassword(client.client_id, { dpop });
		const wrong = await server.startPassword(client.client_id, { dpop });
		const correct = await server.challenge(
			{ auth_session: right.res.body.auth_session, password: TEST_PASSWORD },
			{ proof: await forged() },
		);
		const incorrect = await server.challenge(
			{ auth_session: wrong.res.body.auth_session, password: "wrong-password" },
			{ proof: await forged() },
		);
		expect(correct.status).toBe(400);
		expect(correct.body).toEqual(incorrect.body);
		expect(correct.body.error).toBe("invalid_dpop_proof");
		// Verified before respond runs, so no session was created and the
		// right password's flow is still usable with the real key.
		expect((await server.sessionRows()).length).toBe(sessionsBefore);
		const retry = await server.challenge(
			{ auth_session: right.res.body.auth_session, password: TEST_PASSWORD },
			{ dpop },
		);
		expect(retry.status).toBe(200);
	});
});

describe("first-party apps - required DPoP", async () => {
	const server = await createFpaServer({ plugin: { requireDpop: true } });

	it("requires a proof on the initial request with requireDpop", async () => {
		const client = await server.createClient();
		const starts = server.recording.calls.start;
		const { res } = await server.startOtp(client.client_id);
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_dpop_proof");
		expect(server.recording.calls.start).toBe(starts);
	});
});

describe("first-party apps - DPoP-bound clients", async () => {
	const server = await createFpaServer();

	it("requires a proof for a client registered for DPoP-bound tokens", async () => {
		const client = await server.createClient({
			dpop_bound_access_tokens: true,
		});
		const { res } = await server.startOtp(client.client_id);
		expect(res.body.error).toBe("invalid_dpop_proof");
		const dpop = await createDpopKey();
		const bound = await server.startOtp(client.client_id, { dpop });
		expect(bound.res.status).toBe(403);
	});
});

describe("first-party apps - DPoP nonces", async () => {
	const server = await createFpaServer({
		oauth: { dpop: { nonce: { required: true } } },
	});
	const client = await server.createClient();

	it("asks for a nonce first and keeps the method state for the retry", async () => {
		const dpop = await createDpopKey();
		const first = await server.startOtp(client.client_id, { dpop });
		expect(first.res.status).toBe(400);
		expect(first.res.body.error).toBe("use_dpop_nonce");
		const nonce = first.res.headers.get("dpop-nonce");
		expect(nonce).toEqual(expect.any(String));

		const started = await server.challenge(
			{
				client_id: client.client_id,
				response_type: "code",
				scope: "openid",
				login_hint: "otp:test@test.com",
			},
			{ dpop, nonce: nonce! },
		);
		expect(started.status).toBe(403);
		const next = started.headers.get("dpop-nonce")!;
		expect(next).toEqual(expect.any(String));
		const handle = started.body.auth_session;

		const responds = server.recording.calls.respond;
		const stale = await server.challenge(
			{ auth_session: handle, otp_code: "one" },
			{ dpop },
		);
		expect(stale.body.error).toBe("use_dpop_nonce");
		expect(server.recording.calls.respond).toBe(responds);

		const retried = await server.challenge(
			{ auth_session: handle, otp_code: "one" },
			{ dpop, nonce: stale.headers.get("dpop-nonce")! },
		);
		expect(retried.body).toMatchObject({ challenge_type: "otp", round: 2 });
	});
});
