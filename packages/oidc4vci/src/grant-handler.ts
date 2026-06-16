import type { GenericEndpointContext } from "@better-auth/core";
import type {
	OAuthExtensionGrantHandler,
	OAuthProviderApi,
} from "@better-auth/oauth-provider";
import { APIError } from "better-auth/api";
import { constantTimeEqual, generateRandomString } from "better-auth/crypto";
import { VERIFICATION_TYPES } from "./constants";

const PRE_AUTH_GRANT_TYPE =
	"urn:ietf:params:oauth:grant-type:pre-authorized_code";

type ResolvedClient = NonNullable<
	Awaited<ReturnType<OAuthProviderApi["getClient"]>>
>;

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
	provider: OAuthProviderApi,
	code: string,
	clientId: string | undefined,
	txCode?: string,
): Promise<PreAuthorizedCodeValue> {
	const verification = await ctx.context.internalAdapter.findVerificationValue(
		await provider.hashToken(code, "pre_authorized_code"),
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
		const txCodeHash = await provider.hashToken(txCode, "tx_code");
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
	provider: OAuthProviderApi,
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
		identifier: await provider.hashToken(nonce, "c_nonce"),
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

export function createPreAuthorizedCodeHandler(): OAuthExtensionGrantHandler {
	return async ({ ctx, opts, provider }) => {
		const body = (ctx.body ?? {}) as {
			client_id?: string;
			resource?: string;
			tx_code?: string;
			client_assertion?: string;
			"pre-authorized_code"?: string;
		};
		const preAuthorizedCode = body["pre-authorized_code"];

		if (!preAuthorizedCode) {
			throw new APIError("BAD_REQUEST", {
				error_description: "pre-authorized_code is required",
				error: "invalid_request",
			});
		}

		const value = await checkPreAuthorizedCodeValue(
			ctx,
			provider,
			preAuthorizedCode,
			body.client_id,
			body.tx_code,
		);

		// The pre-authorized code binds the client. Authenticate the caller when it
		// presents a client credential (public clients pass without a secret);
		// otherwise fall back to the client the code was issued to, since the
		// pre-authorized code itself is the authorization.
		const hasClientCredential =
			Boolean(body.client_id) ||
			Boolean(ctx.request?.headers.get("authorization")) ||
			Boolean(body.client_assertion);
		let client: ResolvedClient;
		if (hasClientCredential) {
			({ client } = await provider.authenticateClient({
				scopes: ["openid"],
				requireCredentials: false,
			}));
		} else {
			const resolved = await provider.getClient(value.clientId);
			if (!resolved) {
				throw new APIError("BAD_REQUEST", {
					error_description: "client_id is required",
					error: "invalid_request",
				});
			}
			client = resolved;
		}

		if (value.clientId && client.clientId !== value.clientId) {
			throw new APIError("UNAUTHORIZED", {
				error_description: "invalid client_id",
				error: "invalid_client",
			});
		}

		const user = await ctx.context.internalAdapter.findUserById(value.userId);
		if (!user) {
			throw new APIError("BAD_REQUEST", {
				error_description: "user not found",
				error: "invalid_user",
			});
		}

		const cNonce = await createCNonce(ctx, provider, {
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
			identifier: await provider.hashToken(
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

		// Bind the access token's audience to the credential endpoint (RFC 8707
		// resource indicator) instead of mutating the request body.
		const credentialAudience =
			body.resource ??
			value.credentialAudience ??
			`${ctx.context.baseURL}/oidc4vci/credential`;

		return provider.issueTokens({
			client,
			scopes: ["openid"],
			user,
			resources: [credentialAudience],
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
		});
	};
}

export { PRE_AUTH_GRANT_TYPE };
