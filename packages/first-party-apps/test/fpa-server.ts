import type { BetterAuthOptions } from "@better-auth/core";
import type { OAuthOptions, Scope } from "@better-auth/oauth-provider";
import { oauthProvider } from "@better-auth/oauth-provider";
import type { BetterAuthPlugin } from "better-auth";
import { jwt } from "better-auth/plugins/jwt";
import { getTestInstance } from "better-auth/test";
import type { JWK } from "jose";
import {
	base64url,
	calculateJwkThumbprint,
	decodeJwt,
	exportJWK,
	generateKeyPair,
	SignJWT,
} from "jose";
import type {
	FirstPartyAppsOptions,
	FirstPartyAuthSession,
	FirstPartyMethod,
} from "../src";
import { firstPartyApps, passwordMethod } from "../src";
import { findAuthSession } from "../src/auth-session";

export const BASE_URL = "http://localhost:3000";
export const AUTH_BASE_URL = `${BASE_URL}/api/auth`;
export const CHALLENGE_URL = `${AUTH_BASE_URL}/oauth2/authorize-challenge`;
export const TOKEN_URL = `${AUTH_BASE_URL}/oauth2/token`;
export const TEST_EMAIL = "test@test.com";
export const TEST_PASSWORD = "test123456";

type KeyPair = Awaited<ReturnType<typeof generateKeyPair>>;
export type DpopKey = { keyPair: KeyPair; jwk: JWK; jkt: string };

export async function createDpopKey(): Promise<DpopKey> {
	const keyPair = await generateKeyPair("ES256");
	const jwk = await exportJWK(keyPair.publicKey);
	return { keyPair, jwk, jkt: await calculateJwkThumbprint(jwk) };
}

export async function createDpopProof(
	key: DpopKey,
	input: { url: string; nonce?: string; jwk?: JWK; signWith?: DpopKey },
) {
	return new SignJWT({
		htm: "POST",
		htu: input.url,
		jti: crypto.randomUUID(),
		...(input.nonce ? { nonce: input.nonce } : {}),
	})
		.setProtectedHeader({
			alg: "ES256",
			typ: "dpop+jwt",
			jwk: input.jwk ?? key.jwk,
		})
		.setIssuedAt()
		.sign((input.signWith ?? key).keyPair.privateKey);
}

export async function createPkce() {
	const verifier = `${crypto.randomUUID()}${crypto.randomUUID()}`;
	const digest = await crypto.subtle.digest(
		"SHA-256",
		new TextEncoder().encode(verifier),
	);
	return {
		verifier,
		challenge: base64url.encode(new Uint8Array(digest)),
	};
}

/**
 * A two-round test method for hints of the form `otp:<email>`. The first
 * round answers `otp_code=one` with a second challenge; the second answers
 * `otp_code=two` as authenticated. Anything else fails.
 */
export function createRecordingMethod(id = "otp") {
	const calls = { start: 0, respond: 0, starts: [] as unknown[] };
	const behavior = { failStart: false };
	const method: FirstPartyMethod = {
		id,
		amr: ["otp"],
		responseParameters: [`${id}_code`],
		async start(input) {
			calls.start += 1;
			calls.starts.push({
				loginHint: input.loginHint,
				userId: input.user?.id,
				params: input.params,
				previous: input.previous,
			});
			if (behavior.failStart) return { type: "redirect_to_web" };
			let userId: string | null = null;
			if (input.user) userId = input.user.id;
			else if (input.loginHint?.startsWith(`${id}:`)) {
				const found = await input.ctx.context.internalAdapter.findUserByEmail(
					input.loginHint.slice(id.length + 1),
				);
				userId = found?.user.id ?? null;
			} else return null;
			return {
				type: "challenge",
				userId,
				challenge: { round: 1, error: "overridden", auth_session: "x" },
				state: { round: 1 },
			};
		},
		async respond({ params, state, userId }) {
			calls.respond += 1;
			const round = (state as { round: number }).round;
			const code = params[`${id}_code`];
			if (round === 1 && code === "one") {
				return {
					type: "challenge",
					challenge: { round: 2 },
					state: { round: 2 },
				};
			}
			if (round === 2 && code === "two" && userId) {
				return { type: "authenticated", userId };
			}
			if (code === "web") return { type: "redirect_to_web" };
			return { type: "failed" };
		},
	};
	return { method, calls, behavior };
}

export async function createFpaServer(input?: {
	plugin?: Partial<FirstPartyAppsOptions>;
	methods?: FirstPartyMethod[];
	oauth?: Partial<OAuthOptions<Scope[]>>;
	auth?: Partial<BetterAuthOptions>;
	extraPlugins?: BetterAuthPlugin[];
	/** Send the latest DPoP-Nonce with every proof, retrying once when asked. */
	autoNonce?: boolean;
}) {
	const firstParty = new Set<string>();
	let lastNonce: string | undefined;
	const recording = createRecordingMethod();
	let fetcher: typeof fetch | undefined;
	const options = {
		baseURL: BASE_URL,
		...input?.auth,
		plugins: [
			jwt({ jwt: { issuer: BASE_URL } }),
			oauthProvider({
				loginPage: "/login",
				consentPage: "/consent",
				silenceWarnings: { oauthAuthServerConfig: true, openidConfig: true },
				...input?.oauth,
			}),
			firstPartyApps({
				isFirstPartyClient: ({ client }) => firstParty.has(client.clientId),
				methods: input?.methods ?? [passwordMethod(), recording.method],
				...input?.plugin,
			}),
			...(input?.extraPlugins ?? []),
		],
	} satisfies BetterAuthOptions;
	const instance = await getTestInstance(options);
	fetcher = instance.customFetchImpl as typeof fetch;
	const context = await instance.auth.$context;
	await context.internalAdapter.updateUserByEmail(TEST_EMAIL, {
		emailVerified: true,
	});
	const { headers: adminHeaders } = await instance.signInWithTestUser();
	const auth = instance.auth as unknown as {
		api: Record<string, (input?: any) => Promise<any>>;
		$context: Promise<any>;
	};

	async function createClient(
		body: Record<string, unknown> = {},
		config: { firstParty?: boolean } = {},
	): Promise<{ client_id: string; client_secret?: string }> {
		const client = await auth.api.adminCreateOAuthClient!({
			headers: adminHeaders,
			body: {
				redirect_uris: ["https://app.example/callback"],
				token_endpoint_auth_method: "none",
				grant_types: ["authorization_code", "refresh_token"],
				skip_consent: true,
				...body,
			},
		});
		if (config.firstParty !== false) firstParty.add(client.client_id);
		return client;
	}

	async function post(
		url: string,
		params: Record<string, string | string[]>,
		config: {
			dpop?: DpopKey;
			proof?: string;
			nonce?: string;
			json?: boolean;
			headers?: Record<string, string>;
		} = {},
	) {
		const headers: Record<string, string> = { ...config.headers };
		let body: string;
		if (config.json) {
			headers["content-type"] = "application/json";
			body = JSON.stringify(params);
		} else {
			headers["content-type"] = "application/x-www-form-urlencoded";
			const form = new URLSearchParams();
			for (const [name, value] of Object.entries(params)) {
				for (const item of Array.isArray(value) ? value : [value]) {
					form.append(name, item);
				}
			}
			body = form.toString();
		}
		const autoNonce = !!input?.autoNonce && !config.nonce && !config.proof;
		const send = async (nonce: string | undefined) => {
			if (config.proof) headers.dpop = config.proof;
			else if (config.dpop) {
				headers.dpop = await createDpopProof(config.dpop, { url, nonce });
			}
			const response = await fetcher!(url, { method: "POST", headers, body });
			const next = response.headers.get("dpop-nonce");
			if (next) lastNonce = next;
			return response;
		};
		let res = await send(autoNonce ? lastNonce : config.nonce);
		if (autoNonce && config.dpop && res.status === 400) {
			const retry = res.clone();
			const error = (
				(await retry.json().catch(() => ({}))) as { error?: string }
			).error;
			if (error === "use_dpop_nonce") res = await send(lastNonce);
		}
		const text = await res.text();
		let json: Record<string, any> = {};
		try {
			json = JSON.parse(text);
		} catch {}
		return { status: res.status, headers: res.headers, body: json };
	}

	const challenge = (
		params: Record<string, string | string[]>,
		config?: Parameters<typeof post>[2],
	) => post(CHALLENGE_URL, params, config);

	async function startPassword(
		clientId: string,
		config: { dpop?: DpopKey; extra?: Record<string, string> } = {},
	) {
		const pkce = await createPkce();
		const res = await challenge(
			{
				client_id: clientId,
				response_type: "code",
				scope: "openid offline_access",
				login_hint: TEST_EMAIL,
				code_challenge: pkce.challenge,
				code_challenge_method: "S256",
				...config.extra,
			},
			{ dpop: config.dpop },
		);
		return { res, pkce };
	}

	/** Hint, password, code. Returns the code and the PKCE verifier. */
	async function signIn(
		clientId: string,
		config: {
			dpop?: DpopKey;
			extra?: Record<string, string>;
			password?: string;
		} = {},
	) {
		const { res, pkce } = await startPassword(clientId, config);
		if (res.status !== 403) {
			throw new Error(`initial request failed: ${JSON.stringify(res.body)}`);
		}
		const final = await challenge(
			{
				auth_session: res.body.auth_session,
				password: config.password ?? TEST_PASSWORD,
			},
			{ dpop: config.dpop },
		);
		return { final, pkce, handle: res.body.auth_session as string };
	}

	async function redeem(
		clientId: string,
		code: string,
		verifier: string,
		config: { dpop?: DpopKey; extra?: Record<string, string> } = {},
	) {
		return post(
			TOKEN_URL,
			{
				grant_type: "authorization_code",
				client_id: clientId,
				code,
				code_verifier: verifier,
				...config.extra,
			},
			{ dpop: config.dpop },
		);
	}

	async function authSessionRows(): Promise<FirstPartyAuthSession[]> {
		const ctx = await auth.$context;
		return ctx.adapter.findMany({ model: "firstPartyAuthSession" });
	}

	async function findRow(handle: string) {
		const ctx = await auth.$context;
		return findAuthSession({ context: ctx } as never, handle);
	}

	async function updateRow(id: string, update: Record<string, unknown>) {
		const ctx = await auth.$context;
		await ctx.adapter.update({
			model: "firstPartyAuthSession",
			where: [{ field: "id", value: id }],
			update,
		});
	}

	/** Starts the recording method's flow for the test user. */
	async function startOtp(
		clientId: string,
		config: { dpop?: DpopKey; extra?: Record<string, string> } = {},
	) {
		const pkce = await createPkce();
		const res = await challenge(
			{
				client_id: clientId,
				response_type: "code",
				scope: "openid",
				login_hint: `otp:${TEST_EMAIL}`,
				code_challenge: pkce.challenge,
				code_challenge_method: "S256",
				...config.extra,
			},
			{ dpop: config.dpop },
		);
		return { res, pkce, handle: res.body.auth_session as string };
	}

	async function sessionRows(): Promise<
		Array<{ id: string; token: string; userId: string; createdAt: Date }>
	> {
		const ctx = await auth.$context;
		return ctx.adapter.findMany({ model: "session" });
	}

	return {
		auth,
		firstParty,
		recording,
		adminHeaders,
		customFetchImpl: fetcher,
		createClient,
		post,
		challenge,
		startPassword,
		signIn,
		redeem,
		authSessionRows,
		sessionRows,
		findRow,
		updateRow,
		startOtp,
		decodeJwt,
	};
}

export type FpaServer = Awaited<ReturnType<typeof createFpaServer>>;
