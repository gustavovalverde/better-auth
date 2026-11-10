import type {
	OAuthExtensionGrantHandler,
	OAuthProviderApi,
} from "@better-auth/oauth-provider";
import {
	toResourceList,
	validateClientScopes,
} from "@better-auth/oauth-provider/internal";
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

function invalidGrant(description: string): never {
	throw new APIError("BAD_REQUEST", {
		error: "invalid_grant",
		error_description: description,
	});
}

function parseCodeValue(raw: string): PreAuthorizedCodeValue | null {
	try {
		const value = JSON.parse(raw) as PreAuthorizedCodeValue;
		return value?.type === VERIFICATION_TYPES.PRE_AUTH_CODE ? value : null;
	} catch {
		return null;
	}
}

/**
 * Token-endpoint handler for the pre-authorized code grant (OID4VCI 1.0 §6.1).
 *
 * Everything that can refuse the request runs before the one-time code is
 * claimed, so a rejected `tx_code`, client, resource, or DPoP proof leaves the
 * code for a corrected retry. The code is then claimed atomically, so two
 * concurrent redemptions yield exactly one token response. Proof nonces come
 * from the Nonce Endpoint, so the token response carries no `c_nonce`.
 */
export function createPreAuthorizedCodeHandler(): OAuthExtensionGrantHandler {
	return async ({ ctx, opts, provider }) => {
		const body = (ctx.body ?? {}) as {
			client_id?: string;
			resource?: string | string[];
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

		const identifier = await provider.hashToken(
			preAuthorizedCode,
			"pre_authorized_code",
		);
		const verification =
			await ctx.context.internalAdapter.findVerificationValue(identifier);
		const value = verification ? parseCodeValue(verification.value) : null;
		if (!verification || !value) {
			invalidGrant("invalid pre-authorized code");
		}
		if (!verification.expiresAt || verification.expiresAt <= new Date()) {
			await ctx.context.internalAdapter.deleteVerificationByIdentifier(
				identifier,
			);
			invalidGrant("pre-authorized code expired");
		}
		if (body.client_id && value.clientId !== body.client_id) {
			invalidGrant("pre-authorized code was issued to another client");
		}

		if (value.txCodeHash) {
			if (!body.tx_code) {
				invalidGrant("tx_code required");
			}
			const txCodeHash = await provider.hashToken(body.tx_code, "tx_code");
			if (!constantTimeEqual(txCodeHash, value.txCodeHash)) {
				invalidGrant("invalid tx_code");
			}
		}

		// The pre-authorized code binds the client. Authenticate the caller when
		// it presents a client credential (public clients pass without a
		// secret); otherwise this is anonymous access (OID4VCI 1.0 §6.1) and the
		// code's own client is used.
		const hasClientCredential =
			Boolean(body.client_id) ||
			Boolean(ctx.request?.headers.get("authorization")) ||
			Boolean(body.client_assertion);
		let client: ResolvedClient;
		let proven: Awaited<
			ReturnType<OAuthProviderApi["authenticateClient"]>
		>["confirmation"];
		if (hasClientCredential) {
			const authenticated = await provider.authenticateClient({
				scopes: ["openid"],
				requireCredentials: false,
			});
			client = authenticated.client;
			proven = authenticated.confirmation;
		} else {
			const resolved = await provider.getClient(value.clientId);
			if (!resolved || resolved.disabled) {
				throw new APIError("BAD_REQUEST", {
					error_description: "client_id is required",
					error: "invalid_request",
				});
			}
			// authenticateClient enforces these for an identified client.
			if (!resolved.grantTypes?.includes(PRE_AUTH_GRANT_TYPE)) {
				throw new APIError("BAD_REQUEST", {
					error_description: `client is not authorized to use grant type ${PRE_AUTH_GRANT_TYPE}`,
					error: "unauthorized_client",
				});
			}
			validateClientScopes(resolved, ["openid"]);
			client = resolved;
		}
		if (client.clientId !== value.clientId) {
			invalidGrant("pre-authorized code was issued to another client");
		}

		const user = await ctx.context.internalAdapter.findUserById(value.userId);
		if (!user) {
			throw new APIError("BAD_REQUEST", {
				error_description: "user not found",
				error: "invalid_grant",
			});
		}

		// The token's audience is the credential endpoint the offer was made
		// for. A `resource` parameter may only name that audience: issueTokens
		// does not re-check resources, and the code must not mint user tokens
		// for another protected resource.
		const credentialAudience =
			value.credentialAudience ?? `${ctx.context.baseURL}/oidc4vci/credential`;
		const requestedResources = toResourceList(body.resource) ?? [];
		if (
			requestedResources.some((resource) => resource !== credentialAudience)
		) {
			throw new APIError("BAD_REQUEST", {
				error: "invalid_target",
				error_description:
					"resource must be the credential endpoint this offer was issued for",
			});
		}
		const resources = [credentialAudience];
		const scopes = ["openid"];

		// A rejected DPoP proof refuses here, before the code is claimed.
		const confirmation = await provider.resolveConfirmation({
			client,
			scopes,
			resources,
			confirmation: proven,
		});

		const claimed =
			await ctx.context.internalAdapter.consumeVerificationValue(identifier);
		if (!claimed) {
			invalidGrant("invalid pre-authorized code");
		}

		const credentialIdentifier = generateRandomString(32, "a-z", "A-Z", "0-9");
		const now = new Date();
		const credentialIdentifierExpiresAt = new Date(
			now.getTime() + (opts.accessTokenExpiresIn ?? 3600) * 1000,
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
			? (value.authorizationDetails as Record<string, unknown>[])
			: [
					{
						type: "openid_credential",
						credential_configuration_id: value.credentialConfigurationId,
					},
				];

		const authorizationDetails = rawAuthorizationDetails.map((detail) => {
			if (
				!detail ||
				typeof detail !== "object" ||
				detail.type !== "openid_credential"
			) {
				return detail;
			}
			return {
				...detail,
				credential_configuration_id:
					detail.credential_configuration_id ?? value.credentialConfigurationId,
				credential_identifiers: detail.credential_identifiers ?? [
					credentialIdentifier,
				],
			};
		});

		return provider.issueTokens({
			client,
			scopes,
			user,
			resources,
			confirmation,
			accessTokenClaims: {
				authorization_details: authorizationDetails,
				credential_configuration_id: value.credentialConfigurationId,
				issuer_state: value.issuerState,
			},
			tokenResponse: {
				authorization_details: authorizationDetails,
			},
		});
	};
}

export { PRE_AUTH_GRANT_TYPE };
