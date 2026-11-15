import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { describe, expect, it } from "vitest";
import type { FirstPartyStepUpInput } from "../src";
import { challengeFirstPartyStepUp } from "../src";
import type { DpopKey } from "./fpa-server";
import {
	CHALLENGE_URL,
	createDpopKey,
	createDpopProof,
	createFpaServer,
	createPkce,
	TEST_PASSWORD,
	TOKEN_URL,
} from "./fpa-server";

/** Stands in for an app's refresh-token check that finds the grant too weak. */
let stepUp: FirstPartyStepUpInput | null = null;
const stepUpPlugin = {
	id: "test-step-up",
	hooks: {
		before: [
			{
				matcher: (ctx) =>
					ctx.path === "/oauth2/token" &&
					(ctx.body as { grant_type?: string } | undefined)?.grant_type ===
						"refresh_token" &&
					stepUp !== null,
				handler: createAuthMiddleware(async (ctx) => {
					await challengeFirstPartyStepUp(ctx, stepUp!);
					throw new APIError("BAD_REQUEST", {
						error: "interaction_required",
						error_description: "caller refusal",
					});
				}),
			},
		],
	},
} satisfies BetterAuthPlugin;

describe("first-party apps - token-endpoint step-up", async () => {
	const server = await createFpaServer({
		extraPlugins: [stepUpPlugin],
		oauth: { dpop: { nonce: { required: true } } },
		autoNonce: true,
	});
	const client = await server.createClient({ enable_end_session: true });

	async function grant(clientId = client.client_id) {
		const dpop = await createDpopKey();
		const { final, pkce } = await server.signIn(clientId, { dpop });
		const tokens = await server.redeem(
			clientId,
			final.body.authorization_code,
			pkce.verifier,
			{ dpop },
		);
		expect(tokens.status).toBe(200);
		const idToken = server.decodeJwt(tokens.body.id_token);
		return {
			dpop,
			refreshToken: tokens.body.refresh_token as string,
			userId: idToken.sub as string,
			sessionId: idToken.sid as string,
		};
	}

	function refresh(
		facts: { refreshToken: string },
		config: { dpop?: DpopKey; proof?: string; clientId?: string } = {},
	) {
		return server.post(
			TOKEN_URL,
			{
				grant_type: "refresh_token",
				refresh_token: facts.refreshToken,
				client_id: config.clientId ?? client.client_id,
			},
			config,
		);
	}

	function input(
		facts: { userId: string; sessionId: string | null; dpop: DpopKey | null },
		overrides: Partial<FirstPartyStepUpInput> = {},
	): FirstPartyStepUpInput {
		return {
			clientId: client.client_id,
			userId: facts.userId,
			sessionId: facts.sessionId,
			dpopJkt: facts.dpop?.jkt ?? null,
			request: {
				scope: "openid offline_access",
				acr_values: "urn:example:strong",
			},
			...overrides,
		};
	}

	it("answers 403 insufficient_authorization with an auth_session, no-store, and a nonce", async () => {
		const facts = await grant();
		stepUp = input(facts);
		const res = await refresh(facts, { dpop: facts.dpop });
		expect(res.status).toBe(403);
		expect(res.body).toEqual({
			error: "insufficient_authorization",
			error_description: expect.any(String),
			auth_session: expect.any(String),
		});
		expect(res.headers.get("cache-control")).toBe("no-store");
		expect(res.headers.get("dpop-nonce")).toEqual(expect.any(String));
		const row = await server.findRow(res.body.auth_session);
		expect(row).toMatchObject({
			state: "authenticated",
			sessionId: facts.sessionId,
			ownsSession: false,
			dpopJkt: facts.dpop.jkt,
		});
	});

	it("issues a code on the grant's session when the follow-up passes", async () => {
		const facts = await grant();
		stepUp = input(facts);
		const res = await refresh(facts, { dpop: facts.dpop });
		const pkce = await createPkce();
		const follow = await server.challenge(
			{
				auth_session: res.body.auth_session,
				code_challenge: pkce.challenge,
				code_challenge_method: "S256",
			},
			{ dpop: facts.dpop },
		);
		expect(follow.status).toBe(200);
		stepUp = null;
		const tokens = await server.redeem(
			client.client_id,
			follow.body.authorization_code,
			pkce.verifier,
			{ dpop: facts.dpop },
		);
		expect(server.decodeJwt(tokens.body.id_token).sid).toBe(facts.sessionId);
		expect(tokens.body.auth_session).toEqual(expect.any(String));
	});

	it("re-authenticates when the step-up asks for max_age=0, keeping the grant's session", async () => {
		const facts = await grant();
		stepUp = input(facts, {
			request: {
				scope: "openid",
				max_age: 0,
				acr_values: "urn:example:strong",
			},
		});
		const res = await refresh(facts, { dpop: facts.dpop });
		const pkce = await createPkce();
		const follow = await server.challenge(
			{
				auth_session: res.body.auth_session,
				code_challenge: pkce.challenge,
				code_challenge_method: "S256",
			},
			{ dpop: facts.dpop },
		);
		expect(follow.body).toMatchObject({
			error: "insufficient_authorization",
			challenge_type: "password",
		});
		for (let attempt = 0; attempt < 3; attempt++) {
			await server.challenge(
				{ auth_session: res.body.auth_session, password: "wrong-password" },
				{ dpop: facts.dpop },
			);
		}
		const sessions = await server.sessionRows();
		expect(sessions.some((session) => session.id === facts.sessionId)).toBe(
			true,
		);
	});

	it("keeps follow-ups within the grant", async () => {
		const facts = await grant();
		stepUp = input(facts);
		const res = await refresh(facts, { dpop: facts.dpop });
		const pkce = await createPkce();
		const wider = await server.challenge(
			{
				auth_session: res.body.auth_session,
				scope: "openid offline_access profile",
				code_challenge: pkce.challenge,
				code_challenge_method: "S256",
			},
			{ dpop: facts.dpop },
		);
		expect(wider.status).toBe(400);
		expect(wider.body.error).toBe("invalid_scope");
		const narrower = await server.challenge(
			{
				auth_session: res.body.auth_session,
				scope: "openid",
				code_challenge: pkce.challenge,
				code_challenge_method: "S256",
			},
			{ dpop: facts.dpop },
		);
		expect(narrower.status).toBe(200);
	});

	it("resolves for a non-first-party client and for a client without the authorization_code grant", async () => {
		const facts = await grant();
		server.firstParty.delete(client.client_id);
		stepUp = input(facts);
		const demoted = await refresh(facts, { dpop: facts.dpop });
		server.firstParty.add(client.client_id);
		expect(demoted.status).toBe(400);
		expect(demoted.body.error).toBe("interaction_required");

		const machine = await server.createClient({
			grant_types: ["client_credentials"],
			token_endpoint_auth_method: "client_secret_post",
		});
		stepUp = input(facts, { clientId: machine.client_id });
		const ineligible = await refresh(facts, { dpop: facts.dpop });
		expect(ineligible.body.error).toBe("interaction_required");
	});

	it("rejects a token request authenticated as another client", async () => {
		const facts = await grant();
		const other = await server.createClient();
		stepUp = input(facts);
		const res = await refresh(facts, {
			dpop: facts.dpop,
			clientId: other.client_id,
		});
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_client");
	});

	it("rejects a proof from a key other than the grant's", async () => {
		const facts = await grant();
		stepUp = input(facts);
		const res = await refresh(facts, { dpop: await createDpopKey() });
		expect(res.body.error).toBe("invalid_dpop_proof");
	});

	it("reuses one row per client, user, session, and key with a new handle", async () => {
		const facts = await grant();
		stepUp = input(facts);
		const first = await refresh(facts, { dpop: facts.dpop });
		const second = await refresh(facts, { dpop: facts.dpop });
		expect(second.body.auth_session).not.toBe(first.body.auth_session);
		const rows = (await server.authSessionRows()).filter(
			(row) => row.sessionId === facts.sessionId && row.ceiling,
		);
		expect(rows).toHaveLength(1);
		const stale = await server.challenge(
			{ auth_session: first.body.auth_session },
			{ dpop: facts.dpop },
		);
		expect(stale.body.error).toBe("invalid_session");
	});

	it("does not create a sessionless row for a public client without a DPoP binding", async () => {
		const facts = await grant();
		stepUp = input({ ...facts, sessionId: null, dpop: null });
		const before = (await server.authSessionRows()).length;
		const res = await refresh(facts, { dpop: facts.dpop });
		expect(res.body.error).toBe("interaction_required");
		expect((await server.authSessionRows()).length).toBe(before);
	});

	it("starts no challenge on a sessionless row before the request proves its key", async () => {
		const facts = await grant();
		stepUp = input({ ...facts, sessionId: null });
		const res = await refresh(facts, { dpop: facts.dpop });
		expect(res.status).toBe(403);
		expect((await server.findRow(res.body.auth_session))?.state).toBe(
			"pending",
		);
		const starts = server.recording.calls.start;
		const forged = await server.challenge(
			{ auth_session: res.body.auth_session },
			{
				proof: await createDpopProof(facts.dpop, {
					url: CHALLENGE_URL,
					signWith: await createDpopKey(),
				}),
			},
		);
		expect(forged.body.error).toBe("invalid_dpop_proof");
		expect(server.recording.calls.start).toBe(starts);

		const pkce = await createPkce();
		const follow = await server.challenge(
			{
				auth_session: res.body.auth_session,
				code_challenge: pkce.challenge,
				code_challenge_method: "S256",
			},
			{ dpop: facts.dpop },
		);
		expect(follow.body).toMatchObject({ challenge_type: "password" });
		const done = await server.challenge(
			{ auth_session: res.body.auth_session, password: TEST_PASSWORD },
			{ dpop: facts.dpop },
		);
		expect(done.status).toBe(200);
	});

	it("answers redirect_to_web with re-authentication hints when no method can challenge the user", async () => {
		const ctx = await server.auth.$context;
		const user = await ctx.internalAdapter.createUser({
			email: "passwordless@example.com",
			name: "Passwordless",
			emailVerified: true,
		});
		const facts = await grant();
		stepUp = input({ userId: user.id, sessionId: null, dpop: facts.dpop });
		const res = await refresh(facts, { dpop: facts.dpop });
		expect(res.status).toBe(403);
		server.recording.behavior.failStart = true;
		const follow = await server.challenge(
			{ auth_session: res.body.auth_session },
			{ dpop: facts.dpop },
		);
		server.recording.behavior.failStart = false;
		expect(follow.status).toBe(403);
		expect(follow.body).toMatchObject({
			error: "redirect_to_web",
			acr_values: "urn:example:strong",
			max_age: 0,
		});
		expect(follow.body.auth_session).toBeUndefined();
	});
});
