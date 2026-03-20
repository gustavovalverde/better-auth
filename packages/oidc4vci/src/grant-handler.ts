import type { GenericEndpointContext } from "@better-auth/core";
import type { OAuthOptions, Scope } from "@better-auth/oauth-provider";
import {
	basicToClientCredentials,
	createUserTokens,
	storeToken,
	validateClientCredentials,
} from "@better-auth/oauth-provider";
import { APIError } from "better-auth/api";
import { constantTimeEqual, generateRandomString } from "better-auth/crypto";
import { VERIFICATION_TYPES } from "./constants";

const PRE_AUTH_GRANT_TYPE =
	"urn:ietf:params:oauth:grant-type:pre-authorized_code";

type PreAuthorizedCodeValue = {
	type: "pre_authorized_code";
	clientId: string;
	userId: string;
	credentialConfigurationId: string;
	issuerState?: string;
	txCodeHash?: string;
	authorizationDetails?: unknown;
	credentialAudience?: string;
};

async function checkPreAuthorizedCodeValue(
	ctx: GenericEndpointContext,
	opts: OAuthOptions<Scope[]>,
	code: string,
	clientId: string | undefined,
	txCode?: string,
): Promise<PreAuthorizedCodeValue> {
	const verification = await ctx.context.internalAdapter.findVerificationValue(
		await storeToken(opts.storeTokens, code, "pre_authorized_code"),
	);
	const verificationValue = verification
		? JSON.parse(verification.value)
		: null;

	if (!verification) {
		throw new APIError("UNAUTHORIZED", {
			error_description: "Invalid pre-authorized code",
			error: "invalid_grant",
		});
	}

	if (!verification.expiresAt || verification.expiresAt < new Date()) {
		await ctx.context.internalAdapter.deleteVerificationByIdentifier(
			verification.identifier,
		);
		throw new APIError("UNAUTHORIZED", {
			error_description: "pre-authorized code expired",
			error: "invalid_grant",
		});
	}

	if (
		!verificationValue ||
		verificationValue.type !== VERIFICATION_TYPES.PRE_AUTH_CODE
	) {
		throw new APIError("UNAUTHORIZED", {
			error_description: "incorrect verification type",
			error: "invalid_grant",
		});
	}

	if (clientId && verificationValue.clientId !== clientId) {
		throw new APIError("UNAUTHORIZED", {
			error_description: "invalid client_id",
			error: "invalid_client",
		});
	}

	if (verificationValue.txCodeHash) {
		if (!txCode) {
			throw new APIError("UNAUTHORIZED", {
				error_description: "tx_code required",
				error: "invalid_grant",
			});
		}
		const txCodeHash = await storeToken(opts.storeTokens, txCode, "tx_code");
		if (!constantTimeEqual(txCodeHash, verificationValue.txCodeHash)) {
			throw new APIError("UNAUTHORIZED", {
				error_description: "invalid tx_code",
				error: "invalid_grant",
			});
		}
	}

	// One-time use: delete after all checks pass.
	await ctx.context.internalAdapter.deleteVerificationByIdentifier(
		verification.identifier,
	);

	return verificationValue as PreAuthorizedCodeValue;
}

async function createCNonce(
	ctx: GenericEndpointContext,
	opts: OAuthOptions<Scope[]>,
	data: {
		userId: string;
		clientId: string;
		expiresInSeconds: number;
	},
) {
	const nonce = generateRandomString(32, "a-z", "A-Z", "0-9");
	const iat = Math.floor(Date.now() / 1000);
	const exp = iat + data.expiresInSeconds;

	await ctx.context.internalAdapter.createVerificationValue({
		identifier: await storeToken(opts.storeTokens, nonce, "c_nonce"),
		value: JSON.stringify({
			type: VERIFICATION_TYPES.C_NONCE,
			userId: data.userId,
			clientId: data.clientId,
		}),
		createdAt: new Date(iat * 1000),
		updatedAt: new Date(iat * 1000),
		expiresAt: new Date(exp * 1000),
	});

	return { nonce, expiresIn: data.expiresInSeconds };
}

export function createPreAuthorizedCodeHandler() {
	return async (ctx: GenericEndpointContext, opts: OAuthOptions<Scope[]>) => {
		let { client_id, client_secret, resource, tx_code } = ctx.body as {
			client_id?: string;
			client_secret?: string;
			resource?: string;
			tx_code?: string;
		};
		const preAuthorizedCode = (ctx.body as { "pre-authorized_code"?: string })[
			"pre-authorized_code"
		];

		const authorization = ctx.request?.headers.get("authorization") || null;

		if (authorization?.startsWith("Basic ")) {
			const res = basicToClientCredentials(authorization);
			client_id = res?.client_id;
			client_secret = res?.client_secret;
		}

		if (!preAuthorizedCode) {
			throw new APIError("BAD_REQUEST", {
				error_description: "pre-authorized_code is required",
				error: "invalid_request",
			});
		}

		const value = await checkPreAuthorizedCodeValue(
			ctx,
			opts,
			preAuthorizedCode,
			client_id,
			tx_code,
		);

		const effectiveClientId = client_id ?? value.clientId;
		if (!effectiveClientId) {
			throw new APIError("BAD_REQUEST", {
				error_description: "client_id is required",
				error: "invalid_request",
			});
		}

		const assertionType: string | undefined = ctx.body?.client_assertion_type;
		const assertion: string | undefined = ctx.body?.client_assertion;
		const client = await validateClientCredentials(
			ctx,
			opts,
			effectiveClientId,
			client_secret,
			["openid"],
			assertionType && assertion ? { assertionType, assertion } : undefined,
		);

		// Default audience to credential endpoint for JWT access tokens
		if (!resource) {
			ctx.body.resource =
				value.credentialAudience ??
				`${ctx.context.baseURL}/oidc4vci/credential`;
		} else {
			ctx.body.resource = resource;
		}

		const user = await ctx.context.internalAdapter.findUserById(value.userId);
		if (!user) {
			throw new APIError("BAD_REQUEST", {
				error_description: "user not found",
				error: "invalid_user",
			});
		}

		const cNonce = await createCNonce(ctx, opts, {
			userId: user.id,
			clientId: client.clientId,
			expiresInSeconds: 300,
		});

		const credentialIdentifier = generateRandomString(32, "a-z", "A-Z", "0-9");
		const now = new Date();
		const credentialIdentifierExpiresInSeconds =
			opts.accessTokenExpiresIn ?? 3600;
		const credentialIdentifierExpiresAt = new Date(
			now.getTime() + credentialIdentifierExpiresInSeconds * 1000,
		);
		await ctx.context.internalAdapter.createVerificationValue({
			identifier: await storeToken(
				opts.storeTokens,
				credentialIdentifier,
				"credential_identifier",
			),
			value: JSON.stringify({
				type: VERIFICATION_TYPES.CREDENTIAL_IDENTIFIER,
				userId: user.id,
				clientId: client.clientId,
				credentialConfigurationId: value.credentialConfigurationId,
				issuerState: value.issuerState,
			}),
			createdAt: now,
			updatedAt: now,
			expiresAt: credentialIdentifierExpiresAt,
		});

		const rawAuthorizationDetails = Array.isArray(value.authorizationDetails)
			? value.authorizationDetails
			: ([
					{
						type: "openid_credential",
						credential_configuration_id: value.credentialConfigurationId,
					},
				] as Record<string, unknown>[]);

		const authorizationDetails = rawAuthorizationDetails.map((detail) => {
			if (
				!detail ||
				typeof detail !== "object" ||
				(detail as { type?: string }).type !== "openid_credential"
			) {
				return detail;
			}
			const typed = detail as Record<string, unknown>;
			return {
				...typed,
				credential_configuration_id:
					typed.credential_configuration_id ?? value.credentialConfigurationId,
				credential_identifiers: typed.credential_identifiers ?? [
					credentialIdentifier,
				],
			};
		});

		return createUserTokens(
			ctx,
			opts,
			client,
			["openid"],
			user,
			undefined,
			undefined,
			undefined,
			undefined,
			undefined,
			{
				accessTokenClaims: {
					authorization_details: authorizationDetails,
					credential_configuration_id: value.credentialConfigurationId,
					issuer_state: value.issuerState,
				},
				tokenResponse: {
					authorization_details: authorizationDetails,
					c_nonce: cNonce.nonce,
					c_nonce_expires_in: cNonce.expiresIn,
				},
			},
		);
	};
}

export { PRE_AUTH_GRANT_TYPE };
