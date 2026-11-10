import type { GenericEndpointContext } from "@better-auth/core";
import { BetterAuthError } from "@better-auth/core/error";
import { createOpenid4vpAuthorizationRequest } from "@openid4vc/openid4vp";
import { APIError } from "better-auth/api";
import { generateRandomString } from "better-auth/crypto";
import { DcqlQuery } from "dcql";
import type { JWK } from "jose";
import { calculateJwkThumbprint, importJWK, SignJWT } from "jose";
import type { Awaitable } from "./types";
import { certificatePublicJwk, computeX509Hash, toX5cEntry } from "./x5c";

const JWK_PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
const VP_SESSION_MODEL = "haipVpSession";

export type VpResponseMode = "direct_post" | "direct_post.jwt";

export type HaipVerifierOptions = {
	/**
	 * Certificate chain of the request-signing key, leaf first (PEM or base64
	 * DER). It is sent as the request object's `x5c` header, and the leaf
	 * determines the `x509_hash:` Client Identifier (OID4VP 1.0 §5.9.3).
	 */
	x5c: string[];
	/** Private JWK of the leaf certificate's key, or a resolver for it. */
	signingKey: JWK | (() => Awaitable<JWK>);
	/**
	 * JWS algorithm for request objects.
	 *
	 * @default "ES256"
	 */
	signingAlgorithm?: string;
	/**
	 * Public keys wallets encrypt `direct_post.jwt` responses to, advertised
	 * as `client_metadata.jwks`. Required for encrypted responses.
	 */
	encryptionKeys?: JWK[];
	/**
	 * Content encryption algorithms advertised as
	 * `client_metadata.encrypted_response_enc_values_supported`.
	 *
	 * @default ["A128GCM", "A256GCM"]
	 */
	encryptedResponseEncValues?: string[];
	/**
	 * The `response_uri` wallets post responses to.
	 *
	 * @default `${baseURL}/oidc4vp/response`
	 */
	responseUri?: string;
	/** Additional `client_metadata` members, such as `vp_formats_supported`. */
	clientMetadata?: Record<string, unknown>;
};

export type VpSessionRecord = {
	id: string;
	sessionId: string;
	nonce: string;
	state: string;
	dcqlQuery: string;
	responseUri: string;
	clientId: string;
	responseMode: string;
	requestObject: string;
	expiresAt: Date;
};

/** The authorization request a VP session's request object carries. */
export type VpAuthorizationRequest = {
	response_type: "vp_token";
	response_mode: VpResponseMode;
	response_uri: string;
	client_id: string;
	nonce: string;
	state: string;
	dcql_query: Record<string, unknown>;
};

function publicPart(jwk: JWK): JWK {
	return Object.fromEntries(
		Object.entries(jwk).filter(
			([member]) => !JWK_PRIVATE_MEMBERS.includes(member),
		),
	) as JWK;
}

/** The verifier's `x509_hash:` Client Identifier. */
export async function getVerifierClientId(verifier: HaipVerifierOptions) {
	const leaf = verifier.x5c[0];
	if (!leaf) {
		throw new BetterAuthError(
			"haip verifier.x5c must contain the leaf certificate",
		);
	}
	return `x509_hash:${await computeX509Hash(leaf)}`;
}

function parseDcqlQuery(raw: unknown) {
	try {
		const input = typeof raw === "string" ? JSON.parse(raw) : raw;
		const query = DcqlQuery.parse(input as DcqlQuery.Input);
		DcqlQuery.validate(query);
		return query;
	} catch (error) {
		throw new APIError("BAD_REQUEST", {
			error: "invalid_request",
			error_description: `invalid dcql_query: ${error instanceof Error ? error.message : "parse failed"}`,
		});
	}
}

/**
 * Creates a VP session and its signed request object (JAR, RFC 9101) per
 * HAIP §5.1: the request object is signed with the verifier key, carries the
 * `x5c` chain, and uses the `x509_hash:` Client Identifier Prefix. Wallets
 * fetch it by reference from `request_uri`.
 */
export async function createVpSession(
	ctx: GenericEndpointContext,
	verifier: HaipVerifierOptions,
	input: {
		dcqlQuery: unknown;
		responseMode: VpResponseMode;
		expiresInSeconds: number;
	},
) {
	const dcqlQuery = parseDcqlQuery(input.dcqlQuery);
	if (
		input.responseMode === "direct_post.jwt" &&
		!verifier.encryptionKeys?.length
	) {
		throw new APIError("BAD_REQUEST", {
			error: "invalid_request",
			error_description:
				"direct_post.jwt requires haip verifier.encryptionKeys",
		});
	}

	const baseURL = ctx.context.baseURL;
	const sessionId = generateRandomString(32);
	const nonce = generateRandomString(32);
	const state = generateRandomString(32);
	const clientId = await getVerifierClientId(verifier);
	const responseUri = verifier.responseUri ?? `${baseURL}/oidc4vp/response`;
	const requestUri = `${baseURL}/haip/vp/request-object?session_id=${sessionId}`;
	const algorithm = verifier.signingAlgorithm ?? "ES256";
	const signingJwk =
		typeof verifier.signingKey === "function"
			? await verifier.signingKey()
			: verifier.signingKey;
	// The x509_hash Client Identifier only means something if the request
	// object is signed by the leaf certificate's key.
	const [leafThumbprint, signingThumbprint] = await Promise.all([
		calculateJwkThumbprint(certificatePublicJwk(verifier.x5c[0]!)),
		calculateJwkThumbprint(publicPart(signingJwk)),
	]);
	if (leafThumbprint !== signingThumbprint) {
		throw new BetterAuthError(
			"haip verifier.signingKey does not match the leaf certificate in verifier.x5c",
		);
	}
	const signingKey = await importJWK(signingJwk, algorithm);

	const clientMetadata: Record<string, unknown> = {
		...verifier.clientMetadata,
		...(input.responseMode === "direct_post.jwt"
			? {
					jwks: { keys: verifier.encryptionKeys!.map(publicPart) },
					encrypted_response_enc_values_supported:
						verifier.encryptedResponseEncValues ?? ["A128GCM", "A256GCM"],
				}
			: {}),
	};

	const jwtSigner = {
		method: "x5c" as const,
		alg: algorithm,
		x5c: verifier.x5c.map(toX5cEntry),
	};
	const created = await createOpenid4vpAuthorizationRequest({
		authorizationRequestPayload: {
			response_type: "vp_token",
			response_mode: input.responseMode,
			response_uri: responseUri,
			client_id: clientId,
			nonce,
			state,
			dcql_query: dcqlQuery,
			...(Object.keys(clientMetadata).length
				? { client_metadata: clientMetadata }
				: {}),
		},
		jar: {
			requestUri,
			jwtSigner,
			expiresInSeconds: input.expiresInSeconds,
		},
		callbacks: {
			signJwt: async (_signer, jwt) => ({
				jwt: await new SignJWT(jwt.payload)
					.setProtectedHeader(
						jwt.header as Parameters<SignJWT["setProtectedHeader"]>[0],
					)
					.sign(signingKey),
				signerJwk: publicPart(signingJwk) as never,
			}),
			encryptJwe: async () => {
				throw new Error("request object encryption is not supported");
			},
		},
	});
	const requestObject = created.jar?.authorizationRequestJwt;
	if (!requestObject) {
		throw new APIError("INTERNAL_SERVER_ERROR", {
			error: "server_error",
			error_description: "failed to sign the request object",
		});
	}

	const expiresAt = new Date(Date.now() + input.expiresInSeconds * 1000);
	await ctx.context.adapter.create({
		model: VP_SESSION_MODEL,
		data: {
			sessionId,
			nonce,
			state,
			dcqlQuery: JSON.stringify(dcqlQuery),
			responseUri,
			clientId,
			responseMode: input.responseMode,
			requestObject,
			expiresAt,
		},
	});

	return {
		session_id: sessionId,
		client_id: clientId,
		request_uri: requestUri,
		authorization_request: created.authorizationRequest,
		nonce,
		state,
		expires_in: input.expiresInSeconds,
	};
}

async function findLiveSession(
	ctx: GenericEndpointContext,
	field: "sessionId" | "state",
	value: string,
) {
	const record = await ctx.context.adapter.findOne<VpSessionRecord>({
		model: VP_SESSION_MODEL,
		where: [{ field, value }],
	});
	if (!record) return null;
	if (new Date(record.expiresAt) <= new Date()) {
		await ctx.context.adapter.delete({
			model: VP_SESSION_MODEL,
			where: [{ field: "id", value: record.id }],
		});
		return null;
	}
	return record;
}

/** Returns the signed request object of a live VP session. */
export async function getVpRequestObject(
	ctx: GenericEndpointContext,
	sessionId: string,
) {
	return (
		(await findLiveSession(ctx, "sessionId", sessionId))?.requestObject ?? null
	);
}

/**
 * Creates the `resolveAuthorizationRequest` callback for the oidc4vp plugin,
 * which looks up the authorization request a wallet response answers by its
 * `state`, so the response is checked against the session's nonce, DCQL query,
 * response mode, and Client Identifier rather than values the wallet supplies.
 */
export function createVpSessionResolver() {
	return async (input: {
		state: string;
		ctx: GenericEndpointContext;
	}): Promise<VpAuthorizationRequest | null> => {
		const record = await findLiveSession(input.ctx, "state", input.state);
		if (!record) return null;
		return {
			response_type: "vp_token",
			response_mode: record.responseMode as VpResponseMode,
			response_uri: record.responseUri,
			client_id: record.clientId,
			nonce: record.nonce,
			state: record.state,
			dcql_query: JSON.parse(record.dcqlQuery) as Record<string, unknown>,
		};
	};
}
