import { createHash } from "@better-auth/utils/hash";
import { parseOpenid4VpAuthorizationResponsePayload } from "@openid4vc/openid4vp";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthEndpoint } from "better-auth/api";
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

type VerifiedPresentation = {
	issuer?: string;
	subject?: string;
	claims: Record<string, unknown>;
	status?: number;
};

export type Oidc4vpOptions = {
	resolveIssuerJwks: (issuer: string) => Awaitable<Jwk[]>;
	/** Verifier identifier for kb-jwt audience validation. */
	expectedAudience: string;
	allowedIssuers?: string[];
	verifyStatusList?: boolean;
	statusListFetch?: (uri: string) => Awaitable<string>;
	requiredClaimKeys?: string[];
	clockSkewSeconds?: number;
};

const verifyBodySchema = z.object({
	vp_token: z.any(),
	nonce: z.string(),
	presentation_submission: z.any().optional(),
});

const responseBodySchema = z.record(z.string(), z.any());

function flattenVpTokens(vpToken: unknown) {
	if (typeof vpToken === "string") return [vpToken];
	if (Array.isArray(vpToken)) {
		return vpToken.filter(
			(token): token is string => typeof token === "string",
		);
	}
	if (vpToken && typeof vpToken === "object") {
		const values = Object.values(vpToken as Record<string, unknown>);
		const tokens: string[] = [];
		for (const value of values) {
			if (typeof value === "string") {
				tokens.push(value);
				continue;
			}
			if (Array.isArray(value)) {
				for (const entry of value) {
					if (typeof entry === "string") tokens.push(entry);
				}
			}
		}
		return tokens;
	}
	return [];
}

function parseJsonIfObjectLike(value: string) {
	const trimmed = value.trim();
	if (!trimmed) return value;
	const start = trimmed[0];
	if (start !== "{" && start !== "[") return value;
	try {
		return JSON.parse(trimmed) as unknown;
	} catch {
		return value;
	}
}

function normalizeAuthorizationResponseBody(body: Record<string, unknown>) {
	const normalized = { ...body };
	if (typeof normalized.presentation_submission === "string") {
		normalized.presentation_submission = parseJsonIfObjectLike(
			normalized.presentation_submission,
		);
	}
	if (typeof normalized.vp_token === "string") {
		normalized.vp_token = parseJsonIfObjectLike(normalized.vp_token);
	}
	return normalized;
}

type DescriptorMapEntry = {
	id: string;
	format: string;
	path: string;
};

type PresentationSubmission = {
	id: string;
	definition_id: string;
	descriptor_map: DescriptorMapEntry[];
};

function validatePresentationSubmission(
	raw: unknown,
	tokenCount: number,
): PresentationSubmission | null {
	if (!raw || typeof raw !== "object") return null;
	const sub = raw as Record<string, unknown>;
	if (typeof sub.id !== "string" || typeof sub.definition_id !== "string") {
		throw new APIError("BAD_REQUEST", {
			error: "invalid_request",
			error_description:
				"presentation_submission must have id and definition_id",
		});
	}
	if (!Array.isArray(sub.descriptor_map)) {
		throw new APIError("BAD_REQUEST", {
			error: "invalid_request",
			error_description: "presentation_submission must have descriptor_map",
		});
	}
	for (const entry of sub.descriptor_map) {
		if (
			!entry ||
			typeof entry !== "object" ||
			typeof entry.id !== "string" ||
			typeof entry.format !== "string" ||
			typeof entry.path !== "string"
		) {
			throw new APIError("BAD_REQUEST", {
				error: "invalid_request",
				error_description:
					"descriptor_map entries must have id, format, and path",
			});
		}
	}
	if (sub.descriptor_map.length !== tokenCount) {
		throw new APIError("BAD_REQUEST", {
			error: "invalid_request",
			error_description: "descriptor_map length must match vp_token count",
		});
	}
	return {
		id: sub.id,
		definition_id: sub.definition_id,
		descriptor_map: sub.descriptor_map as DescriptorMapEntry[],
	};
}

async function verifyAuthorizationResponsePayload(
	ctx: { setStatus: (status: any) => void; json: (...args: any[]) => any },
	payload: Record<string, unknown>,
	options: Oidc4vpOptions,
) {
	const vpTokens = flattenVpTokens(payload.vp_token);
	if (!vpTokens.length) {
		throw new APIError("BAD_REQUEST", {
			error: "invalid_request",
			error_description: "vp_token is required",
		});
	}

	const nonce = typeof payload.nonce === "string" ? payload.nonce : undefined;
	if (!nonce) {
		throw new APIError("BAD_REQUEST", {
			error: "invalid_request",
			error_description: "nonce is required",
		});
	}

	const submission = validatePresentationSubmission(
		payload.presentation_submission,
		vpTokens.length,
	);

	const results: VerifiedPresentation[] = [];
	const errors: { index: number; message: string }[] = [];

	for (const [index, token] of vpTokens.entries()) {
		try {
			const result = await verifySdJwtPresentation(token, options, nonce);
			results.push(result);
		} catch (error) {
			const message =
				error instanceof Error ? error.message : "verification failed";
			errors.push({ index, message });
		}
	}

	if (errors.length) {
		ctx.setStatus(400);
		return ctx.json({ verified: false, errors });
	}

	const response: {
		verified: boolean;
		presentations: VerifiedPresentation[];
		presentation_submission?: PresentationSubmission;
		state?: string;
	} = {
		verified: true,
		presentations: results,
	};

	if (submission) {
		response.presentation_submission = submission;
	}

	if (typeof payload.state === "string") {
		response.state = payload.state;
	}

	return ctx.json(response);
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
			throw new APIError("BAD_REQUEST", {
				error: "invalid_request",
				error_description: `unsupported hash alg: ${alg}`,
			});
		}
		const buffer =
			typeof data === "string"
				? new TextEncoder().encode(data)
				: new Uint8Array(data);
		const hash = await createHash("SHA-256").digest(buffer);
		return new Uint8Array(hash);
	};
}

function createIssuerVerifier(jwks: Jwk[]) {
	return async (data: string, signature: string) => {
		const header = parseHeader(data, signature);
		const alg = typeof header?.alg === "string" ? header.alg : undefined;
		const kid = typeof header?.kid === "string" ? header.kid : undefined;
		if (!alg) return false;
		const candidates = jwks.filter((jwk) => !kid || jwk.kid === kid);
		if (!candidates.length) return false;
		for (const jwk of candidates) {
			try {
				const key = await importJWK(jwk, alg);
				await compactVerify(`${data}.${signature}`, key);
				return true;
			} catch {
				continue;
			}
		}
		return false;
	};
}

function createKeyBindingVerifier(options: Oidc4vpOptions) {
	return async (
		data: string,
		signature: string,
		payload?: Record<string, unknown>,
	) => {
		const header = parseHeader(data, signature);
		const jwk = header?.jwk;
		const alg = typeof header?.alg === "string" ? header.alg : undefined;
		if (!jwk || !alg) return false;
		try {
			const key = await importJWK(jwk as Jwk, alg);
			await compactVerify(`${data}.${signature}`, key);
		} catch {
			return false;
		}

		// Validate kb-jwt audience matches verifier identifier
		const kbPayload = decodeJwt(`${data}.${signature}`);
		if (kbPayload.aud !== options.expectedAudience) return false;

		// Validate kb-jwt freshness
		const now = Math.floor(Date.now() / 1000);
		const maxAge = 300;
		const skew = options.clockSkewSeconds ?? 0;
		if (
			typeof kbPayload.iat === "number" &&
			kbPayload.iat < now - maxAge - skew
		) {
			return false;
		}

		// Validate holder binding via cnf
		const cnf = (
			payload as { cnf?: { jkt?: unknown; jwk?: unknown } } | undefined
		)?.cnf;
		const kbThumbprint = await calculateJwkThumbprint(jwk as Jwk);

		if (cnf?.jkt && typeof cnf.jkt === "string") {
			if (kbThumbprint !== cnf.jkt) return false;
		} else if (cnf?.jwk && typeof cnf.jwk === "object") {
			const credentialThumbprint = await calculateJwkThumbprint(cnf.jwk as Jwk);
			if (kbThumbprint !== credentialThumbprint) return false;
		}

		return true;
	};
}

async function resolveIssuerKeys(options: Oidc4vpOptions, issuer: string) {
	if (options.allowedIssuers && !options.allowedIssuers.includes(issuer)) {
		throw new APIError("BAD_REQUEST", {
			error: "invalid_request",
			error_description: "issuer not allowed",
		});
	}
	const jwks = await options.resolveIssuerJwks(issuer);
	if (!jwks?.length) {
		throw new APIError("BAD_REQUEST", {
			error: "invalid_request",
			error_description: "issuer jwks not found",
		});
	}
	return jwks;
}

function createStatusListFetcher(options: Oidc4vpOptions) {
	if (options.verifyStatusList === false) return undefined;
	return async (uri: string) => {
		if (options.statusListFetch) {
			return await options.statusListFetch(uri);
		}
		const res = await fetch(uri);
		if (!res.ok) {
			throw new APIError("BAD_REQUEST", {
				error: "invalid_request",
				error_description: "failed to fetch status list",
			});
		}
		return await res.text();
	};
}

function createStatusVerifier(options: Oidc4vpOptions) {
	if (options.verifyStatusList === false) return undefined;
	return async (data: string, signature: string) => {
		const header = parseHeader(data, signature);
		const alg = typeof header?.alg === "string" ? header.alg : undefined;
		const kid = typeof header?.kid === "string" ? header.kid : undefined;
		if (!alg) return false;

		const payload = decodeJwt(`${data}.${signature}`);
		const issuer = typeof payload.iss === "string" ? payload.iss : undefined;
		if (!issuer) return false;

		const jwks = await options.resolveIssuerJwks(issuer);
		const candidates = jwks.filter((jwk) => !kid || jwk.kid === kid);
		if (!candidates.length) return false;
		for (const jwk of candidates) {
			try {
				const key = await importJWK(jwk, alg);
				await compactVerify(`${data}.${signature}`, key);
				return true;
			} catch {
				continue;
			}
		}
		return false;
	};
}

async function verifySdJwtPresentation(
	vpToken: string,
	options: Oidc4vpOptions,
	nonce: string,
): Promise<VerifiedPresentation> {
	const [credentialJwt] = vpToken.split("~");
	if (!credentialJwt) {
		throw new APIError("BAD_REQUEST", {
			error: "invalid_request",
			error_description: "invalid vp_token",
		});
	}

	const decoded = decodeJwt(credentialJwt);
	const issuer = typeof decoded.iss === "string" ? decoded.iss : undefined;
	if (!issuer) {
		throw new APIError("BAD_REQUEST", {
			error: "invalid_request",
			error_description: "missing issuer",
		});
	}

	const jwks = await resolveIssuerKeys(options, issuer);

	const verifier = createIssuerVerifier(jwks);
	const hasher = createHasher();
	const keyBindingVerifier = createKeyBindingVerifier(options);

	const sdjwt = new SDJwtVcInstance({
		hasher,
		verifier,
		kbVerifier: keyBindingVerifier,
		statusListFetcher: createStatusListFetcher(options),
		statusVerifier: createStatusVerifier(options),
	});

	let verified: { payload: unknown };
	try {
		verified = await sdjwt.verify(vpToken, {
			currentDate: Math.floor(Date.now() / 1000),
			skewSeconds: options.clockSkewSeconds,
			requiredClaimKeys: options.requiredClaimKeys,
			keyBindingNonce: nonce,
		});
	} catch (error) {
		const description =
			error instanceof Error ? error.message : "invalid vp_token";
		throw new APIError("BAD_REQUEST", {
			error: "invalid_grant",
			error_description: description,
		});
	}

	const payload = (verified.payload ?? {}) as Record<string, unknown>;
	if (payload.iss !== issuer) {
		throw new APIError("BAD_REQUEST", {
			error: "invalid_grant",
			error_description: "issuer mismatch",
		});
	}

	const statusRef = payload.status as {
		status_list?: { idx?: number };
	} | null;
	const statusValue = statusRef?.status_list?.idx !== undefined ? 0 : undefined;

	return {
		issuer,
		subject: typeof payload.sub === "string" ? payload.sub : undefined,
		claims: payload,
		status: statusValue,
	};
}

export function oidc4vp(options: Oidc4vpOptions): BetterAuthPlugin {
	return {
		id: "oidc4vp",
		schema,
		options,
		endpoints: {
			verifyPresentation: createAuthEndpoint(
				"/oidc4vp/verify",
				{
					method: "POST",
					body: verifyBodySchema,
				},
				async (ctx) => {
					let parsedBody: Record<string, unknown>;
					try {
						parsedBody = parseOpenid4VpAuthorizationResponsePayload(
							ctx.body as Record<string, unknown>,
						);
					} catch (error) {
						const description =
							error instanceof Error
								? error.message
								: "invalid authorization response payload";
						throw new APIError("BAD_REQUEST", {
							error: "invalid_request",
							error_description: description,
						});
					}

					return await verifyAuthorizationResponsePayload(
						ctx,
						parsedBody,
						options,
					);
				},
			),
			response: createAuthEndpoint(
				"/oidc4vp/response",
				{
					method: "POST",
					body: responseBodySchema,
					metadata: {
						allowedMediaTypes: [
							"application/x-www-form-urlencoded",
							"application/json",
						],
					},
				},
				async (ctx) => {
					const rawBody = ctx.body as Record<string, unknown>;
					if (typeof rawBody.response === "string") {
						throw new APIError("BAD_REQUEST", {
							error: "unsupported_response_type",
							error_description: "direct_post.jwt (JARM) is not supported",
						});
					}

					const normalizedBody = normalizeAuthorizationResponseBody(rawBody);
					let parsedBody: Record<string, unknown>;
					try {
						parsedBody =
							parseOpenid4VpAuthorizationResponsePayload(normalizedBody);
					} catch (error) {
						const description =
							error instanceof Error
								? error.message
								: "invalid authorization response payload";
						throw new APIError("BAD_REQUEST", {
							error: "invalid_request",
							error_description: description,
						});
					}

					return await verifyAuthorizationResponsePayload(
						ctx,
						parsedBody,
						options,
					);
				},
			),
		},
	} satisfies BetterAuthPlugin;
}
