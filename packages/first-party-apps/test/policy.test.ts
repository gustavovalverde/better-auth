import { describe, expect, it } from "vitest";
import type {
	FirstPartyAuthorizationDecision,
	FirstPartyAuthorizationPolicyInput,
} from "../src";
import type { DpopKey } from "./fpa-server";
import {
	createDpopKey,
	createFpaServer,
	createPkce,
	TEST_PASSWORD,
} from "./fpa-server";

describe("first-party apps - authorization policy", async () => {
	let decision: FirstPartyAuthorizationDecision;
	const inputs: FirstPartyAuthorizationPolicyInput[] = [];
	const server = await createFpaServer({
		plugin: {
			authorizationPolicy: (input) => {
				inputs.push(input);
				return decision;
			},
		},
	});
	const client = await server.createClient({ enable_end_session: true });

	async function present(
		handle: string,
		dpop: DpopKey,
		extra: Record<string, string> = {},
	) {
		const pkce = await createPkce();
		const res = await server.challenge(
			{
				auth_session: handle,
				code_challenge: pkce.challenge,
				code_challenge_method: "S256",
				...extra,
			},
			{ dpop },
		);
		return { res, pkce };
	}

	it("postpones issuance and issues on the same session once the policy passes", async () => {
		decision = {
			type: "insufficient_authorization",
			description: 'Verify your "identity" first\\',
			fields: { tier: 2, auth_session: "ignored" },
		};
		const dpop = await createDpopKey();
		const { final, handle } = await server.signIn(client.client_id, { dpop });
		expect(final.status).toBe(403);
		expect(final.body).toEqual({
			error: "insufficient_authorization",
			error_description: "Verify your identity first",
			auth_session: handle,
			tier: 2,
		});
		expect(inputs.at(-1)?.authentication).toMatchObject({
			fresh: true,
			amr: ["pwd"],
		});
		const row = await server.findRow(handle);
		expect(row?.state).toBe("authenticated");

		decision = undefined;
		const first = await present(handle, dpop);
		expect(first.res.status).toBe(200);
		expect(inputs.at(-1)?.authentication.fresh).toBe(false);
		const firstTokens = await server.redeem(
			client.client_id,
			first.res.body.authorization_code,
			first.pkce.verifier,
			{ dpop },
		);
		const second = await present(firstTokens.body.auth_session, dpop);
		expect(second.res.status).toBe(200);
		const secondTokens = await server.redeem(
			client.client_id,
			second.res.body.authorization_code,
			second.pkce.verifier,
			{ dpop },
		);
		const firstId = server.decodeJwt(firstTokens.body.id_token);
		const secondId = server.decodeJwt(secondTokens.body.id_token);
		expect(firstId.sid).toEqual(expect.any(String));
		expect(secondId.sid).toBe(firstId.sid);
		expect(secondId.auth_time).toBe(firstId.auth_time);
		expect(
			(await server.findRow(secondTokens.body.auth_session))?.sessionId,
		).toBe(row?.sessionId);
	});

	it.each<Record<string, string>>([{ prompt: "login" }, { max_age: "0" }])(
		"issues on the postponed sign-in's session for %o",
		async (extra) => {
			decision = { type: "insufficient_authorization" };
			const dpop = await createDpopKey();
			const sessionsBefore = (await server.sessionRows()).length;
			const { final, handle } = await server.signIn(client.client_id, {
				dpop,
				extra,
			});
			expect(final.status).toBe(403);
			expect(final.body.error).toBe("insufficient_authorization");
			const row = await server.findRow(handle);

			decision = undefined;
			const { res } = await present(handle, dpop);
			expect(res.status).toBe(200);
			expect(res.body.authorization_code).toEqual(expect.any(String));
			expect((await server.findRow(handle))?.sessionId).toBe(row?.sessionId);
			expect((await server.sessionRows()).length).toBe(sessionsBefore + 1);
		},
	);

	it("challenges the user again for reauthenticate and creates a new session", async () => {
		decision = undefined;
		const dpop = await createDpopKey();
		const { handle } = await server.signIn(client.client_id, { dpop });
		const before = await server.findRow(handle);

		decision = { type: "reauthenticate" };
		const { res } = await present(handle, dpop);
		expect(res.body).toMatchObject({
			error: "insufficient_authorization",
			challenge_type: "password",
		});
		decision = undefined;
		const done = await server.challenge(
			{ auth_session: handle, password: TEST_PASSWORD },
			{ dpop },
		);
		expect(done.status).toBe(200);
		expect((await server.findRow(handle))?.sessionId).not.toBe(
			before?.sessionId,
		);
	});

	it("treats reauthenticate after a fresh sign-in as redirect_to_web", async () => {
		decision = { type: "reauthenticate" };
		const { final } = await server.signIn(client.client_id);
		expect(final.status).toBe(403);
		expect(final.body.error).toBe("redirect_to_web");
	});

	it("answers redirect_to_web", async () => {
		decision = {
			type: "redirect_to_web",
			description: "Finish in the browser",
		};
		const { final } = await server.signIn(client.client_id);
		expect(final.status).toBe(403);
		expect(final.body).toEqual({
			error: "redirect_to_web",
			error_description: "Finish in the browser",
		});
	});
});

describe("first-party apps - re-entry (Appendix A.7)", async () => {
	const server = await createFpaServer();
	const client = await server.createClient();

	it("challenges again for acr_values and max_age=0 without response_type", async () => {
		const dpop = await createDpopKey();
		const { final, handle } = await server.signIn(client.client_id, { dpop });
		expect(final.status).toBe(200);
		const pkce = await createPkce();
		const res = await server.challenge(
			{
				auth_session: handle,
				acr_values: "urn:example:strong",
				max_age: "0",
				code_challenge: pkce.challenge,
				code_challenge_method: "S256",
			},
			{ dpop },
		);
		expect(res.status).toBe(403);
		expect(res.body).toMatchObject({
			error: "insufficient_authorization",
			challenge_type: "password",
		});
		const done = await server.challenge(
			{ auth_session: handle, password: TEST_PASSWORD },
			{ dpop },
		);
		expect(done.status).toBe(200);
	});

	it("does not reuse a PKCE challenge for a second code", async () => {
		const dpop = await createDpopKey();
		const { handle } = await server.signIn(client.client_id, { dpop });
		const res = await server.challenge({ auth_session: handle }, { dpop });
		expect(res.status).toBe(400);
		expect(res.body.error).toBe("invalid_request");
		expect((await server.findRow(handle))?.state).toBe("authenticated");
	});
});

describe("first-party apps - issuance errors", async () => {
	const server = await createFpaServer();

	it("answers redirect_to_web without consent and deletes the session it created", async () => {
		const client = await server.createClient({ skip_consent: false });
		const before = (await server.sessionRows()).length;
		const { final } = await server.signIn(client.client_id);
		expect(final.status).toBe(403);
		expect(final.body.error).toBe("redirect_to_web");
		expect((await server.sessionRows()).length).toBe(before);
	});

	it("answers invalid_target for an unknown resource and deletes the session it created", async () => {
		const client = await server.createClient();
		const before = (await server.sessionRows()).length;
		const { final } = await server.signIn(client.client_id, {
			extra: { resource: "https://unknown.example/api" },
		});
		expect(final.status).toBe(400);
		expect(final.body.error).toBe("invalid_target");
		expect((await server.sessionRows()).length).toBe(before);
	});
});

describe("first-party apps - session fields", async () => {
	const server = await createFpaServer({
		auth: {
			session: {
				additionalFields: {
					firstPartyMethod: { type: "string", required: false },
				},
			},
		},
		oauth: {
			authenticationContext: {
				acrValuesSupported: ["0"],
				resolve: ({ session }) =>
					session.firstPartyMethod
						? { amr: [`fpa-${session.firstPartyMethod}`] }
						: undefined,
			},
		},
		plugin: {
			session: {
				expiresIn: 600,
				fields: ({ method }) => ({ firstPartyMethod: method, token: "no" }),
			},
		},
	});

	it("stores the fields on the session and reaches authenticationContext.resolve", async () => {
		const client = await server.createClient();
		const dpop = await createDpopKey();
		const { final, pkce, handle } = await server.signIn(client.client_id, {
			dpop,
		});
		const row = await server.findRow(handle);
		const session = (await server.sessionRows()).find(
			(candidate) => candidate.id === row?.sessionId,
		) as unknown as {
			firstPartyMethod: string;
			token: string;
			expiresAt: Date;
		};
		expect(session.firstPartyMethod).toBe("password");
		expect(session.token).not.toBe("no");
		const lifetime = new Date(session.expiresAt).getTime() - Date.now();
		expect(lifetime).toBeLessThanOrEqual(600_000);
		expect(lifetime).toBeGreaterThan(500_000);

		const tokens = await server.redeem(
			client.client_id,
			final.body.authorization_code,
			pkce.verifier,
			{ dpop },
		);
		expect(server.decodeJwt(tokens.body.id_token).amr).toEqual([
			"fpa-password",
		]);
	});
});
