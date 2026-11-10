import type { GenericEndpointContext } from "@better-auth/core";
import { createHash } from "@better-auth/utils/hash";
import {
	parseOpenid4VpAuthorizationResponsePayload,
	parseOpenid4vpAuthorizationResponse,
} from "@openid4vc/openid4vp";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthEndpoint } from "better-auth/api";
import type { JWK } from "jose";
import {
	calculateJwkThumbprint,
	compactVerify,
	decodeJwt,
	decodeProtectedHeader,
	importJWK,
} from "jose";
import * as z from "zod";
import { SD_HASH_ALG } from "./constants";
import { schema } from "./schema";

declare module "@better-auth/core" {
	interface BetterAuthPluginRegistry<AuthOptions, Options> {
		oidc4vp: {
			creator: typeof oidc4vp;
		};
	}
}

type Awaitable<T> = T | Promise<T>;
type Jwk = Record<string, unknown>;

export type VerifiedPresentation = {
	/** The DCQL credential query id the presentation answers (the `vp_token` key). */
	credentialQueryId?: string;
	format: string;
	issuer?: string;
	subject?: string;
	claims: Record<string, unknown>;
	/** Whether a Key Binding JWT was verified against the credential's `cnf`. */
	holderBinding: boolean;
	status?: number;
};

/**
 * The authorization request a wallet response answers, as the verifier issued
 * it. Its `nonce`, `dcql_query`, `client_id`, and `response_mode` are what the
 * response is checked against.
 */
export type Oidc4vpAuthorizationRequest = {
	response_type: "vp_token";
	response_mode: "direct_post" | "direct_post.jwt";
	client_id: string;
	nonce: string;
	state: string;
	dcql_query: Record<string, unknown>;
	response_uri?: string;
	[key: string]: unknown;
};

export type ResponseDecryptor = (input: {
	response: string;
}) => Awaitable<{ payload: string; decryptionJwk?: JWK }>;

export type Oidc4vpOptions = {
	resolveIssuerJwks: (issuer: string) => Awaitable<Jwk[]>;
	/**
	 * Verifier identifier expected as the Key Binding JWT `aud` at
	 * `/oidc4vp/verify`. Responses to a resolved authorization request expect
	 * that request's `client_id` instead (OID4VP 1.0 §B.3.6).
	 */
	expectedAudience: string;
	allowedIssuers?: string[];
	verifyStatusList?: boolean;
	statusListFetch?: (uri: string) => Awaitable<string>;
	requiredClaimKeys?: string[];
	clockSkewSeconds?: number;
	/**
	 * Maximum Key Binding JWT age, measured from its `iat`.
	 *
	 * @default 300
	 */
	keyBindingMaxAgeSeconds?: number;
	/** JWS algorithms accepted for issuer-signed credentials. */
	allowedIssuerAlgorithms?: string[];
	/** JWS algorithms accepted for Key Binding JWTs. */
	allowedKeyBindingAlgorithms?: string[];
	/**
	 * Decryptors for encrypted responses. `direct_post.jwt` responses
	 * (OID4VP 1.0 §8.3) are decrypted with it and then validated against the
	 * authorization request by `@openid4vc/openid4vp`.
	 */
	responseModeHandlers?: {
		"direct_post.jwt"?: ResponseDecryptor;
	};
	/**
	 * Looks up the authorization request a `/oidc4vp/response` submission
	 * answers, by its `state`. Required for that endpoint: a wallet response
	 * carries no nonce or query of its own, so without the original request it
	 * cannot be verified.
	 */
	resolveAuthorizationRequest?: (input: {
		state: string;
		ctx: GenericEndpointContext;
	}) => Awaitable<Oidc4vpAuthorizationRequest | null>;
	/**
	 * Matches verified presentations against the DCQL query (for example
	 * `createDcqlMatcher()` from `@better-auth/haip`). At `/oidc4vp/response`
	 * the query is the resolved request's; at `/oidc4vp/verify` it is the
	 * caller's `dcql_query`.
	 */
	presentationMatcher?: (input: {
		query: unknown;
		presentations: VerifiedPresentation[];
	}) => Awaitable<{
		matched: boolean;
		matchedPresentations: VerifiedPresentation[];
		errors?: string[];
	}>;
};

type PresentationEntry = { credentialQueryId?: string; token: string };

const verifyBodySchema = z.object({
	vp_token: z.union([z.string(), z.record(z.string(), z.unknown())]),
	nonce: z.string(),
	dcql_query: z.record(z.string(), z.unknown()).optional(),
});

const responseBodySchema = z.record(z.string(), z.unknown());

function invalidRequest(description: string): never {
	throw new APIError("BAD_REQUEST", {
		error: "invalid_request",
		error_description: description,
	});
}

/**
 * Flattens a `vp_token` into presentations, keeping the DCQL credential query
 * id each one answers (OID4VP 1.0 §8.1: an object keyed by query id whose
 * values are arrays of presentations).
 */
function flattenVpToken(vpToken: unknown): PresentationEntry[] {
	if (typeof vpToken === "string") return [{ token: vpToken }];
	if (!vpToken || typeof vpToken !== "object" || Array.isArray(vpToken)) {
		return [];
	}
	const entries: PresentationEntry[] = [];
	for (const [credentialQueryId, value] of Object.entries(vpToken)) {
		const values = Array.isArray(value) ? value : [value];
		for (const entry of values) {
			if (typeof entry === "string") {
				entries.push({ credentialQueryId, token: entry });
			}
		}
	}
	return entries;
}

function parseJsonIfObjectLike(value: string) {
	const trimmed = value.trim();
	if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return value;
	try {
		return JSON.parse(trimmed) as unknown;
	} catch {
		return value;
	}
}

function parseHeader(data: string, signature: string) {
	try {
		return decodeProtectedHeader(`${data}.${signature}`) as Record<
			string,
			unknown
		>;
	} catch {
		return null;
	}
}

function createHasher() {
	return async (data: string | ArrayBuffer, alg: string) => {
		if (alg !== SD_HASH_ALG) {
			throw new Error(`unsupported hash alg: ${alg}`);
		}
		const buffer =
			typeof data === "string"
				? new TextEncoder().encode(data)
				: new Uint8Array(data);
		return new Uint8Array(await createHash("SHA-256").digest(buffer));
	};
}

function createJwksVerifier(resolveJwks: (issuer: string) => Awaitable<Jwk[]>) {
	return async (data: string, signature: string) => {
		const header = parseHeader(data, signature);
		const alg = typeof header?.alg === "string" ? header.alg : undefined;
		const kid = typeof header?.kid === "string" ? header.kid : undefined;
		if (!alg || alg === "none" || alg.startsWith("HS")) return false;
		const issuer = decodeJwt(`${data}.${signature}`).iss;
		if (typeof issuer !== "string") return false;
		const jwks = await resolveJwks(issuer);
		for (const jwk of jwks.filter((key) => !kid || key.kid === kid)) {
			try {
				await compactVerify(`${data}.${signature}`, await importJWK(jwk, alg));
				return true;
			} catch {}
		}
		return false;
	};
}

/**
 * Verifies the Key Binding JWT signature with the credential's holder key
 * (`cnf.jwk`). A credential bound only by thumbprint (`cnf.jkt`) is accepted
 * when the KB-JWT header carries the matching `jwk`. A credential without a
 * `cnf` cannot be presented with holder binding. The library checks `typ`,
 * `nonce`, `aud`, `iat`, and `sd_hash`.
 */
async function verifyKeyBinding(
	data: string,
	signature: string,
	payload: Record<string, unknown> | undefined,
) {
	const header = parseHeader(data, signature);
	const alg = typeof header?.alg === "string" ? header.alg : undefined;
	if (!alg) return false;
	const cnf = payload?.cnf as { jwk?: unknown; jkt?: unknown } | undefined;
	let holderKey: Jwk | undefined;
	if (cnf?.jwk && typeof cnf.jwk === "object") {
		holderKey = cnf.jwk as Jwk;
	} else if (
		typeof cnf?.jkt === "string" &&
		header?.jwk &&
		typeof header.jwk === "object" &&
		(await calculateJwkThumbprint(header.jwk as JWK)) === cnf.jkt
	) {
		holderKey = header.jwk as Jwk;
	}
	if (!holderKey) return false;
	try {
		await compactVerify(
			`${data}.${signature}`,
			await importJWK(holderKey, alg),
		);
		return true;
	} catch {
		return false;
	}
}

function createStatusListFetcher(options: Oidc4vpOptions) {
	return async (uri: string) => {
		if (options.statusListFetch) {
			return await options.statusListFetch(uri);
		}
		const res = await fetch(uri, { redirect: "error" });
		if (!res.ok) {
			throw new Error("failed to fetch status list");
		}
		return await res.text();
	};
}

async function verifySdJwtPresentation(
	entry: PresentationEntry,
	options: Oidc4vpOptions,
	expected: { nonce: string; audience: string },
): Promise<VerifiedPresentation> {
	const [credentialJwt] = entry.token.split("~");
	if (!credentialJwt) {
		invalidRequest("invalid vp_token");
	}
	let issuer: string | undefined;
	try {
		const iss = decodeJwt(credentialJwt).iss;
		issuer = typeof iss === "string" ? iss : undefined;
	} catch {
		invalidRequest("invalid vp_token");
	}
	if (!issuer) {
		invalidRequest("missing issuer");
	}
	if (options.allowedIssuers && !options.allowedIssuers.includes(issuer)) {
		invalidRequest("issuer not allowed");
	}
	const issuerJwks = await options.resolveIssuerJwks(issuer);
	if (!issuerJwks?.length) {
		invalidRequest("issuer jwks not found");
	}

	const verifyStatus = options.verifyStatusList !== false;
	const sdjwt = new SDJwtVcInstance({
		hasher: createHasher(),
		verifier: createJwksVerifier(async () => issuerJwks),
		kbVerifier: verifyKeyBinding,
		...(verifyStatus
			? {
					statusListFetcher: createStatusListFetcher(options),
					statusVerifier: createJwksVerifier(options.resolveIssuerJwks),
				}
			: {}),
	});

	let verified: Awaited<ReturnType<typeof sdjwt.verify>>;
	try {
		verified = await sdjwt.verify(entry.token, {
			currentDate: Math.floor(Date.now() / 1000),
			skewSeconds: options.clockSkewSeconds,
			requiredClaimKeys: options.requiredClaimKeys,
			expectedIssuer: issuer,
			keyBindingNonce: expected.nonce,
			expectedKeyBindingAudience: expected.audience,
			keyBindingMaxAgeSeconds: options.keyBindingMaxAgeSeconds ?? 300,
			disableStatusVerification: !verifyStatus,
			...(options.allowedIssuerAlgorithms
				? { allowedIssuerAlgorithms: options.allowedIssuerAlgorithms }
				: {}),
			...(options.allowedKeyBindingAlgorithms
				? { allowedKeyBindingAlgorithms: options.allowedKeyBindingAlgorithms }
				: {}),
		});
	} catch (error) {
		throw new APIError("BAD_REQUEST", {
			error: "invalid_request",
			error_description:
				error instanceof Error ? error.message : "invalid vp_token",
		});
	}

	const payload = (verified.payload ?? {}) as Record<string, unknown>;
	const header = (verified.header ?? {}) as Record<string, unknown>;
	const statusRef = payload.status as { status_list?: { idx?: number } } | null;
	return {
		...(entry.credentialQueryId
			? { credentialQueryId: entry.credentialQueryId }
			: {}),
		format: typeof header.typ === "string" ? header.typ : "dc+sd-jwt",
		issuer,
		subject: typeof payload.sub === "string" ? payload.sub : undefined,
		claims: payload,
		holderBinding: Boolean(verified.kb),
		status:
			verifyStatus && statusRef?.status_list?.idx !== undefined ? 0 : undefined,
	};
}

async function verifyPresentations(
	ctx: GenericEndpointContext,
	options: Oidc4vpOptions,
	input: {
		entries: PresentationEntry[];
		nonce: string;
		audience: string;
		dcqlQuery?: unknown;
		state?: string;
	},
) {
	if (!input.entries.length) {
		invalidRequest("vp_token is required");
	}
	// OID4VP 1.0 §8.1: vp_token keys are the ids of the query's credential
	// queries, whether or not a presentationMatcher evaluates the query.
	const queryIds = new Set(
		(
			(input.dcqlQuery as { credentials?: Array<{ id?: unknown }> } | undefined)
				?.credentials ?? []
		).map((credential) => credential.id),
	);
	if (
		queryIds.size &&
		input.entries.some(
			(entry) =>
				entry.credentialQueryId !== undefined &&
				!queryIds.has(entry.credentialQueryId),
		)
	) {
		invalidRequest(
			"vp_token contains a credential query id the query does not define",
		);
	}
	const presentations: VerifiedPresentation[] = [];
	const errors: { index: number; message: string }[] = [];
	for (const [index, entry] of input.entries.entries()) {
		try {
			presentations.push(
				await verifySdJwtPresentation(entry, options, {
					nonce: input.nonce,
					audience: input.audience,
				}),
			);
		} catch (error) {
			const message =
				error instanceof APIError
					? String(
							(error.body as { error_description?: unknown })
								?.error_description ?? error.message,
						)
					: error instanceof Error
						? error.message
						: "verification failed";
			errors.push({ index, message });
		}
	}
	if (errors.length) {
		ctx.setStatus(400);
		return ctx.json({ verified: false, errors });
	}

	if (options.presentationMatcher && input.dcqlQuery) {
		const match = await options.presentationMatcher({
			query: input.dcqlQuery,
			presentations,
		});
		if (!match.matched) {
			ctx.setStatus(400);
			return ctx.json({
				verified: false,
				errors: (match.errors ?? ["presentation does not match query"]).map(
					(message, index) => ({ index, message }),
				),
			});
		}
	}

	return ctx.json({
		verified: true,
		presentations,
		...(input.state !== undefined ? { state: input.state } : {}),
	});
}

/** Extracts `state` from a decrypted `direct_post.jwt` payload. */
function readJarmState(plaintext: string): string | undefined {
	try {
		const parsed: unknown = plaintext.trim().startsWith("{")
			? JSON.parse(plaintext)
			: decodeJwt(plaintext);
		const state = (parsed as { state?: unknown }).state;
		return typeof state === "string" ? state : undefined;
	} catch {
		return undefined;
	}
}

export function oidc4vp(options: Oidc4vpOptions) {
	return {
		id: "oidc4vp",
		schema,
		options,
		endpoints: {
			/**
			 * Verifies presentations for a caller that holds the nonce it issued.
			 */
			verifyPresentation: createAuthEndpoint(
				"/oidc4vp/verify",
				{
					method: "POST",
					body: verifyBodySchema,
				},
				async (ctx) => {
					const vpToken =
						typeof ctx.body.vp_token === "string"
							? parseJsonIfObjectLike(ctx.body.vp_token)
							: ctx.body.vp_token;
					return verifyPresentations(ctx, options, {
						entries: flattenVpToken(vpToken),
						nonce: ctx.body.nonce,
						audience: options.expectedAudience,
						dcqlQuery: ctx.body.dcql_query,
					});
				},
			),
			/**
			 * Response endpoint for `direct_post` and `direct_post.jwt`
			 * (OID4VP 1.0 §8.2, §8.3). The response is validated against the
			 * authorization request its `state` identifies.
			 */
			response: createAuthEndpoint(
				"/oidc4vp/response",
				{
					method: "POST",
					body: responseBodySchema,
					metadata: {
						noStore: true,
						allowedMediaTypes: [
							"application/x-www-form-urlencoded",
							"application/json",
						],
					},
				},
				async (ctx) => {
					if (!options.resolveAuthorizationRequest) {
						invalidRequest(
							"the response endpoint requires resolveAuthorizationRequest",
						);
					}
					const rawBody = { ...ctx.body };
					const decryptor = options.responseModeHandlers?.["direct_post.jwt"];

					let state: string | undefined;
					if (typeof rawBody.response === "string") {
						if (!decryptor) {
							invalidRequest("direct_post.jwt requires a response decryptor");
						}
						let plaintext: string;
						try {
							plaintext = (await decryptor({ response: rawBody.response }))
								.payload;
						} catch {
							invalidRequest("unable to decrypt the authorization response");
						}
						state = readJarmState(plaintext);
					} else {
						state =
							typeof rawBody.state === "string" ? rawBody.state : undefined;
						if (typeof rawBody.vp_token === "string") {
							rawBody.vp_token = parseJsonIfObjectLike(rawBody.vp_token);
						}
					}
					if (!state) {
						invalidRequest("state is required");
					}
					const request = await options.resolveAuthorizationRequest({
						state,
						ctx,
					});
					if (!request) {
						invalidRequest("unknown or expired state");
					}

					let parsed: Awaited<
						ReturnType<typeof parseOpenid4vpAuthorizationResponse>
					>;
					try {
						parsed = await parseOpenid4vpAuthorizationResponse({
							authorizationResponse: rawBody,
							authorizationRequestPayload: request as Parameters<
								typeof parseOpenid4vpAuthorizationResponse
							>[0]["authorizationRequestPayload"],
							callbacks: {
								decryptJwe: async (jwe) => {
									if (!decryptor) return { decrypted: false };
									const result = await decryptor({ response: jwe });
									return {
										decrypted: true,
										payload: result.payload,
										decryptionJwk: (result.decryptionJwk ?? {
											kty: "EC",
										}) as never,
									};
								},
								// Wallet-signed responses are not supported; HAIP uses
								// encrypted responses.
								verifyJwt: async () => ({ verified: false }),
							},
						});
					} catch (error) {
						invalidRequest(
							error instanceof Error
								? error.message
								: "invalid authorization response",
						);
					}
					if (parsed.type !== "dcql") {
						invalidRequest("only DCQL presentation responses are supported");
					}
					const vpToken = parseOpenid4VpAuthorizationResponsePayload(
						parsed.authorizationResponsePayload as Record<string, unknown>,
					).vp_token;

					return verifyPresentations(ctx, options, {
						entries: flattenVpToken(vpToken),
						nonce: parsed.expectedNonce,
						audience: request.client_id,
						dcqlQuery: request.dcql_query,
						state,
					});
				},
			),
		},
		rateLimit: [
			{
				pathMatcher: (path: string) =>
					path === "/oidc4vp/verify" || path === "/oidc4vp/response",
				window: 60,
				max: 60,
			},
		],
	} satisfies BetterAuthPlugin;
}
