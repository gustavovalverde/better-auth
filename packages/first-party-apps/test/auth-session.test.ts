import { describe, expect, it } from "vitest";
import {
	CHALLENGE_URL,
	createDpopKey,
	createDpopProof,
	createFpaServer,
	createPkce,
	TEST_PASSWORD,
} from "./fpa-server";

describe("first-party apps - handles and rows", async () => {
	const server = await createFpaServer({
		plugin: { authSession: { maxRequests: 3, maxFailures: 10 } },
	});
	const client = await server.createClient();

	it("issues a 256-bit handle and stores only its hash", async () => {
		const { handle } = await server.startOtp(client.client_id);
		expect(handle).toMatch(/^[A-Za-z0-9_-]{43,}$/);
		const row = await server.findRow(handle);
		expect(row).not.toBeNull();
		expect(row!.authSession).not.toBe(handle);
		const stored = await server.authSessionRows();
		expect(stored.some((candidate) => candidate.authSession === handle)).toBe(
			false,
		);
	});

	it("answers invalid_session for an unknown or expired handle", async () => {
		const unknown = await server.challenge({
			auth_session: "unknown",
			otp_code: "one",
		});
		expect(unknown.status).toBe(400);
		expect(unknown.body.error).toBe("invalid_session");

		const { handle } = await server.startOtp(client.client_id);
		const row = await server.findRow(handle);
		await server.updateRow(row!.id, { expiresAt: new Date(Date.now() - 1000) });
		const expired = await server.challenge({
			auth_session: handle,
			otp_code: "one",
		});
		expect(expired.body.error).toBe("invalid_session");
		expect(await server.findRow(handle)).toBeNull();
	});

	it("issues exactly one code for two concurrent final responses", async () => {
		const { res } = await server.startPassword(client.client_id);
		const send = () =>
			server.challenge({
				auth_session: res.body.auth_session,
				password: TEST_PASSWORD,
			});
		const results = await Promise.all([send(), send()]);
		const codes = results.filter((result) => result.status === 200);
		expect(codes).toHaveLength(1);
		const other = results.find((result) => result.status !== 200)!;
		expect(other.body.error).toBe("invalid_session");
	});

	it("ends a pending row after maxRequests", async () => {
		const { handle } = await server.startOtp(client.client_id);
		for (let request = 0; request < 3; request++) {
			const res = await server.challenge({
				auth_session: handle,
				otp_code: "bad",
			});
			expect(res.body.error).toBe("authentication_failed");
		}
		const limited = await server.challenge({
			auth_session: handle,
			otp_code: "bad",
		});
		expect(limited.body.error).toBe("invalid_session");
		expect(await server.findRow(handle)).toBeNull();
	});

	it("passes the original start parameters and previous state to a restart", async () => {
		const { handle } = await server.startOtp(client.client_id, {
			extra: { chain_id: "10" },
		});
		expect(server.recording.calls.starts.at(-1)).toMatchObject({
			params: { chain_id: "10" },
		});
		await server.challenge({
			auth_session: handle,
			otp_code: "bad",
			chain_id: "1",
		});
		expect(server.recording.calls.starts.at(-1)).toMatchObject({
			loginHint: "otp:test@test.com",
			params: { chain_id: "10" },
			previous: { state: { round: 1 } },
		});
	});

	it("accepts only response parameters while a challenge is pending", async () => {
		const { handle } = await server.startOtp(client.client_id);
		const scoped = await server.challenge({
			auth_session: handle,
			otp_code: "one",
			scope: "openid profile",
		});
		expect(scoped.body.error).toBe("invalid_request");
		const bare = await server.challenge({ auth_session: handle });
		expect(bare.body.error).toBe("invalid_request");
	});
});

describe("first-party apps - session liveness (C2)", async () => {
	const server = await createFpaServer();
	const client = await server.createClient();

	async function loginAgain(
		handle: string,
		dpop: Awaited<ReturnType<typeof createDpopKey>>,
	) {
		const pkce = await createPkce();
		return server.challenge(
			{
				auth_session: handle,
				prompt: "login",
				code_challenge: pkce.challenge,
				code_challenge_method: "S256",
			},
			{ dpop },
		);
	}

	async function authenticatedRow() {
		const dpop = await createDpopKey();
		const { final, handle } = await server.signIn(client.client_id, { dpop });
		expect(final.status).toBe(200);
		const row = await server.findRow(handle);
		expect(row?.state).toBe("authenticated");
		return { dpop, handle, row: row! };
	}

	it("answers invalid_session and deletes the row once the backing session ends", async () => {
		const { dpop, handle, row } = await authenticatedRow();
		const ctx = await server.auth.$context;
		const session = (await server.sessionRows()).find(
			(candidate) => candidate.id === row.sessionId,
		)!;
		await ctx.internalAdapter.deleteSession(session.token);
		const pkce = await createPkce();
		const res = await server.challenge(
			{
				auth_session: handle,
				code_challenge: pkce.challenge,
				code_challenge_method: "S256",
			},
			{ dpop },
		);
		expect(res.body.error).toBe("invalid_session");
		expect(await server.findRow(handle)).toBeNull();
	});

	it("deletes an owned session when re-authentication reaches maxFailures", async () => {
		const { dpop, handle, row } = await authenticatedRow();
		const reauth = await loginAgain(handle, dpop);
		expect(reauth.body).toMatchObject({
			error: "insufficient_authorization",
			challenge_type: "password",
		});
		for (let attempt = 0; attempt < 2; attempt++) {
			const failed = await server.challenge(
				{ auth_session: handle, password: "wrong-password" },
				{ dpop },
			);
			expect(failed.body.error).toBe("authentication_failed");
		}
		const ended = await server.challenge(
			{ auth_session: handle, password: "wrong-password" },
			{ dpop },
		);
		expect(ended.body.error).toBe("redirect_to_web");
		const sessions = await server.sessionRows();
		expect(sessions.some((session) => session.id === row.sessionId)).toBe(
			false,
		);
	});

	it("never ends an authenticated row for a request without the key", async () => {
		const { dpop, handle, row } = await authenticatedRow();
		await loginAgain(handle, dpop);
		const forger = await createDpopKey();
		for (let attempt = 0; attempt < 4; attempt++) {
			const forged = await server.challenge(
				{ auth_session: handle, password: "wrong-password" },
				{
					proof: await createDpopProof(dpop, {
						url: CHALLENGE_URL,
						signWith: forger,
					}),
				},
			);
			expect(forged.body.error).toBe("invalid_dpop_proof");
		}
		expect((await server.findRow(handle))?.failures).toBe(0);
		const sessions = await server.sessionRows();
		expect(sessions.some((session) => session.id === row.sessionId)).toBe(true);
		const correct = await server.challenge(
			{ auth_session: handle, password: TEST_PASSWORD },
			{ dpop },
		);
		expect(correct.status).toBe(200);
	});

	it("moves the row to a new owned session after re-authentication and keeps the old one", async () => {
		const { dpop, handle, row } = await authenticatedRow();
		await loginAgain(handle, dpop);
		const done = await server.challenge(
			{ auth_session: handle, password: TEST_PASSWORD },
			{ dpop },
		);
		expect(done.status).toBe(200);
		const after = await server.findRow(handle);
		expect(after?.sessionId).not.toBe(row.sessionId);
		expect(after?.ownsSession).toBe(true);
		const sessions = await server.sessionRows();
		expect(sessions.some((session) => session.id === row.sessionId)).toBe(true);
	});

	it("deletes a row without a DPoP binding after its code", async () => {
		const { final, handle } = await server.signIn(client.client_id);
		expect(final.status).toBe(200);
		expect(await server.findRow(handle)).toBeNull();
	});
});
