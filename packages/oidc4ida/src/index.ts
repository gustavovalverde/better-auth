import type { OAuthOptions } from "@better-auth/oauth-provider";
import { createHash } from "@better-auth/utils/hash";
import type { BetterAuthPlugin } from "better-auth";
import {
	APIError,
	createAuthEndpoint,
	createAuthMiddleware,
	sessionMiddleware,
} from "better-auth/api";
import type { JwtOptions } from "better-auth/plugins";
import { signJWT } from "better-auth/plugins";
import type { User } from "better-auth/types";
import { decodeJwt } from "jose";
import * as z from "zod";
import { schema } from "./schema";

declare module "@better-auth/core" {
	interface BetterAuthPluginRegistry<AuthOptions, Options> {
		oidc4ida: {
			creator: typeof oidc4ida;
		};
	}
}

type Awaitable<T> = T | Promise<T>;

type VerifiedClaims = {
	verification?: Record<string, unknown>;
	claims?: Record<string, unknown>;
	[key: string]: unknown;
};

type RequestedVerifiedClaims = {
	verification?: Record<string, unknown>;
	claims?: Record<string, unknown>;
};

type ClaimsParameter = {
	id_token?: { verified_claims?: RequestedVerifiedClaims };
	userinfo?: { verified_claims?: RequestedVerifiedClaims };
};

type Oidc4idaMetadata = {
	verified_claims_supported?: boolean;
	claims_parameter_supported?: boolean;
	claims_in_verified_claims_supported?: string[];
	trust_frameworks_supported?: string[];
	evidence_supported?: string[];
	documents_supported?: string[];
	documents_methods_supported?: string[];
	document_check_methods_supported?: string[];
	documents_validation_methods_supported?: string[];
	[key: string]: unknown;
};

export type Oidc4idaOptions = {
	getVerifiedClaims?: (input: {
		user: User;
	}) => Awaitable<VerifiedClaims | null>;
	metadata?: Oidc4idaMetadata;
};

const verifiedClaimsBodySchema = z.object({
	user_id: z.string(),
	verified_claims: z.record(z.string(), z.any()),
});

const REQUESTED_CLAIMS_KEY = "oidc4ida_requested_claims";

function normalizeMetadata(options: Oidc4idaOptions) {
	const result = {
		claims_parameter_supported: true,
		verified_claims_supported: true,
	};
	if (options.metadata) {
		Object.assign(result, options.metadata);
	}
	return result;
}

function parseClaimsParameter(value: unknown): ClaimsParameter | null {
	if (!value) return null;
	if (typeof value === "string") {
		try {
			const parsed = JSON.parse(value) as ClaimsParameter;
			return parsed && typeof parsed === "object" ? parsed : null;
		} catch {
			return null;
		}
	}
	if (typeof value === "object") {
		return value as ClaimsParameter;
	}
	return null;
}

function readBodyParam(body: unknown, key: string): string | null {
	if (!body) return null;
	if (body instanceof URLSearchParams) {
		return body.get(key);
	}
	if (typeof FormData !== "undefined" && body instanceof FormData) {
		const entry = body.get(key);
		return typeof entry === "string" ? entry : null;
	}
	if (typeof body === "string") {
		const params = new URLSearchParams(body);
		return params.get(key);
	}
	if (typeof body === "object") {
		const value = (body as Record<string, unknown>)[key];
		return typeof value === "string" ? value : null;
	}
	return null;
}

function readRequestParam(
	context: { body?: unknown; query?: Record<string, unknown> },
	key: string,
) {
	const bodyValue = readBodyParam(context.body, key);
	if (bodyValue) return bodyValue;
	const queryValue = context.query?.[key];
	return typeof queryValue === "string" ? queryValue : null;
}

async function readRequestBodyParam(
	body: unknown,
	request: Request | undefined,
	key: string,
) {
	const bodyValue = readBodyParam(body, key);
	if (bodyValue) return bodyValue;
	if (!request) return null;
	try {
		const formData = await request.clone().formData();
		const entry = formData.get(key);
		return typeof entry === "string" ? entry : null;
	} catch {
		return null;
	}
}

function extractRequestedVerifiedClaims(
	claimsParam: ClaimsParameter | null | undefined,
	section: "id_token" | "userinfo",
): RequestedVerifiedClaims | null {
	if (!claimsParam) return null;
	const requestedSection = claimsParam[section];
	if (!requestedSection || typeof requestedSection !== "object") return null;
	const verifiedClaims = (requestedSection as ClaimsParameter["id_token"])
		?.verified_claims;
	if (!verifiedClaims || typeof verifiedClaims !== "object") return null;
	const verification =
		verifiedClaims.verification &&
		typeof verifiedClaims.verification === "object"
			? verifiedClaims.verification
			: undefined;
	const claims =
		verifiedClaims.claims && typeof verifiedClaims.claims === "object"
			? verifiedClaims.claims
			: undefined;
	if (!verification && !claims) return null;
	return { verification, claims };
}

function filterObjectClaims(
	source: Record<string, unknown> | undefined,
	requested: Record<string, unknown> | undefined,
) {
	if (!source || !requested) return source;
	const filtered: Record<string, unknown> = {};
	for (const key of Object.keys(requested)) {
		if (Object.hasOwn(source, key)) {
			filtered[key] = source[key];
		}
	}
	return filtered;
}

function applyRequestedVerifiedClaims(
	verifiedClaims: VerifiedClaims,
	requested: RequestedVerifiedClaims,
): VerifiedClaims {
	const filtered = { ...verifiedClaims };
	if (requested.verification) {
		filtered.verification = filterObjectClaims(
			verifiedClaims.verification,
			requested.verification,
		);
	}
	if (requested.claims) {
		filtered.claims = filterObjectClaims(
			verifiedClaims.claims,
			requested.claims,
		);
	}
	return filtered;
}

async function storeTokenIdentifier(
	storeTokens: OAuthOptions["storeTokens"] | undefined,
	token: string,
) {
	if (!storeTokens || storeTokens === "hashed") {
		return await createHash("SHA-256", "base64urlnopad").digest(token);
	}
	if ("hash" in storeTokens) {
		return await storeTokens.hash(token, "authorization_code");
	}
	return await createHash("SHA-256", "base64urlnopad").digest(token);
}

function resolveOauthStoreTokens(ctx: {
	context: { getPlugin: (id: string) => unknown };
}) {
	const plugin = ctx.context.getPlugin("oauth-provider") as {
		options?: OAuthOptions;
	} | null;
	return plugin?.options?.storeTokens;
}

async function resolveClaimsFromAuthorizationCode(ctx: {
	body?: unknown;
	request?: Request;
	context: {
		internalAdapter: { findVerificationValue: Function };
		getPlugin: (id: string) => unknown;
	};
}) {
	const code = await readRequestBodyParam(ctx.body, ctx.request, "code");
	if (typeof code !== "string") return null;
	const identifier = await storeTokenIdentifier(
		resolveOauthStoreTokens(ctx),
		code,
	);
	const verification =
		await ctx.context.internalAdapter.findVerificationValue(identifier);
	if (!verification) return null;
	let parsed: { query?: Record<string, unknown> } | null = null;
	try {
		parsed = JSON.parse(verification.value) as {
			query?: Record<string, unknown>;
		};
	} catch {
		parsed = null;
	}
	if (!parsed?.query) return null;
	return parseClaimsParameter(parsed.query.claims);
}

async function resolveVerifiedClaims(
	ctx: { context: { adapter: { findMany: Function }; internalAdapter: any } },
	options: Oidc4idaOptions,
	userId: string,
): Promise<VerifiedClaims | null> {
	const user = await ctx.context.internalAdapter.findUserById(userId);
	if (!user) return null;

	if (typeof options.getVerifiedClaims === "function") {
		return options.getVerifiedClaims({ user });
	}

	const records = (await ctx.context.adapter.findMany({
		model: "oidc4idaVerifiedClaim",
		where: [{ field: "userId", value: userId }],
		limit: 1,
	})) as { verifiedClaims: string }[];
	if (!records.length) return null;
	try {
		return JSON.parse(records[0]!.verifiedClaims) as VerifiedClaims;
	} catch {
		return null;
	}
}

async function attachVerifiedClaimsToIdToken(
	ctx: any,
	options: Oidc4idaOptions,
) {
	const returned = ctx.context.returned;
	if (
		!returned ||
		typeof returned !== "object" ||
		returned instanceof Response
	) {
		return;
	}
	const tokenResponse = returned as Record<string, unknown>;
	const idToken = tokenResponse.id_token;
	if (typeof idToken !== "string") {
		return;
	}
	// Per OIDC4IDA spec Section 7: only include verified_claims
	// when explicitly requested via the claims parameter.
	const requestedClaims = (ctx.context as Record<string, unknown>)[
		REQUESTED_CLAIMS_KEY
	] as ClaimsParameter | null;
	const requestedVerifiedClaims = extractRequestedVerifiedClaims(
		requestedClaims,
		"id_token",
	);
	if (!requestedVerifiedClaims) {
		return;
	}
	const payload = decodeJwt(idToken);
	const sub = payload.sub;
	if (typeof sub !== "string") {
		return;
	}
	const verifiedClaims = await resolveVerifiedClaims(ctx, options, sub);
	if (!verifiedClaims) {
		return;
	}
	const filteredClaims = applyRequestedVerifiedClaims(
		verifiedClaims,
		requestedVerifiedClaims,
	);

	const jwtPlugin = ctx.context.getPlugin("jwt") as {
		options?: JwtOptions;
	} | null;
	if (!jwtPlugin) {
		throw new APIError("INTERNAL_SERVER_ERROR", {
			message: "jwt plugin is required",
		});
	}

	const updatedIdToken = await signJWT(ctx, {
		options: jwtPlugin.options,
		payload: {
			...payload,
			verified_claims: filteredClaims,
		},
	});

	return {
		response: {
			...tokenResponse,
			id_token: updatedIdToken,
		},
	};
}

async function attachVerifiedClaimsToUserInfo(
	ctx: any,
	options: Oidc4idaOptions,
) {
	const returned = ctx.context.returned;
	if (
		!returned ||
		typeof returned !== "object" ||
		returned instanceof Response
	) {
		return;
	}
	const userInfo = returned as Record<string, unknown>;
	const sub = userInfo.sub;
	if (typeof sub !== "string") {
		return;
	}
	// Per OIDC4IDA spec Section 7: only include verified_claims
	// when explicitly requested via the claims parameter.
	const requestedClaims = parseClaimsParameter(ctx.query?.claims);
	const requestedVerifiedClaims = extractRequestedVerifiedClaims(
		requestedClaims,
		"userinfo",
	);
	if (!requestedVerifiedClaims) {
		return;
	}
	const verifiedClaims = await resolveVerifiedClaims(ctx, options, sub);
	if (!verifiedClaims) {
		return;
	}
	const filteredClaims = applyRequestedVerifiedClaims(
		verifiedClaims,
		requestedVerifiedClaims,
	);
	return {
		response: {
			...userInfo,
			verified_claims: filteredClaims,
		},
	};
}

async function attachOidcMetadata(ctx: any, options: Oidc4idaOptions) {
	const returned = ctx.context.returned;
	if (!returned) return;
	const metadata = normalizeMetadata(options);

	if (returned instanceof Response) {
		let body: Record<string, unknown> | null = null;
		try {
			body = (await returned.clone().json()) as Record<string, unknown>;
		} catch {
			body = null;
		}
		if (!body) return;
		const headers = new Headers(returned.headers);
		headers.set("content-type", "application/json");
		return {
			response: new Response(JSON.stringify({ ...body, ...metadata }), {
				status: returned.status,
				headers,
			}),
		};
	}

	if (typeof returned === "object") {
		return {
			response: {
				...(returned as Record<string, unknown>),
				...metadata,
			},
		};
	}
}

export function oidc4ida(options: Oidc4idaOptions = {}) {
	return {
		id: "oidc4ida",
		schema,
		options,
		endpoints: {
			setVerifiedClaims: createAuthEndpoint(
				"/oidc4ida/verified-claims",
				{
					method: "POST",
					use: [sessionMiddleware],
					body: verifiedClaimsBodySchema,
				},
				async (ctx) => {
					const user = await ctx.context.internalAdapter.findUserById(
						ctx.body.user_id,
					);
					if (!user) {
						throw new APIError("BAD_REQUEST", { message: "user not found" });
					}

					const now = new Date();
					const payload = JSON.stringify(ctx.body.verified_claims);
					const existing = await ctx.context.adapter.findMany<{ id: string }>({
						model: "oidc4idaVerifiedClaim",
						where: [{ field: "userId", value: user.id }],
						limit: 1,
					});

					if (existing.length) {
						await ctx.context.adapter.update({
							model: "oidc4idaVerifiedClaim",
							where: [{ field: "id", value: existing[0]!.id }],
							update: {
								verifiedClaims: payload,
								updatedAt: now,
							},
						});
					} else {
						await ctx.context.adapter.create({
							model: "oidc4idaVerifiedClaim",
							data: {
								userId: user.id,
								verifiedClaims: payload,
								createdAt: now,
								updatedAt: now,
							},
						});
					}

					return ctx.json({
						user_id: user.id,
					});
				},
			),
		},
		hooks: {
			before: [
				{
					matcher: (context) => context.path === "/oauth2/token",
					handler: createAuthMiddleware(async (ctx) => {
						const claimsParam = parseClaimsParameter(
							readRequestParam(ctx, "claims"),
						);
						const resolved =
							claimsParam ??
							(await resolveClaimsFromAuthorizationCode(ctx as any));
						if (resolved) {
							(ctx.context as Record<string, unknown>)[REQUESTED_CLAIMS_KEY] =
								resolved;
						}
					}),
				},
			],
			after: [
				{
					matcher: (context) => context.path === "/oauth2/token",
					handler: createAuthMiddleware(async (ctx) =>
						attachVerifiedClaimsToIdToken(ctx, options),
					),
				},
				{
					matcher: (context) => context.path === "/oauth2/userinfo",
					handler: createAuthMiddleware(async (ctx) =>
						attachVerifiedClaimsToUserInfo(ctx, options),
					),
				},
				{
					matcher: (context) =>
						context.path === "/.well-known/openid-configuration",
					handler: createAuthMiddleware(async (ctx) =>
						attachOidcMetadata(ctx, options),
					),
				},
			],
		},
	} satisfies BetterAuthPlugin;
}
