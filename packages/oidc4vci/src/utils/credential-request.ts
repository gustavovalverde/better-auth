import type { CredentialConfiguration, Oidc4vciOptions } from "../types";

type CredentialRequestParams = {
	format?: unknown;
	vct?: unknown;
	doctype?: unknown;
	credentialDefinition?: unknown;
};

/**
 * Matches a credential configuration by format and format-specific parameters.
 *
 * Supports dc+sd-jwt, vc+sd-jwt, mso_mdoc, and jwt_vc_json formats.
 */
export function matchCredentialConfigurationByFormat(
	configurations: Oidc4vciOptions["credentialConfigurations"],
	params: CredentialRequestParams,
): CredentialConfiguration | null {
	const { format, vct, doctype, credentialDefinition } = params;

	if (typeof format !== "string") return null;

	return (
		configurations.find((cfg) => {
			const cfgFormat = cfg.format ?? "dc+sd-jwt";
			if (cfgFormat !== format) return false;

			if (format === "dc+sd-jwt" || format === "vc+sd-jwt") {
				if (vct && typeof vct === "string") {
					return cfg.vct === vct;
				}
			}

			if (format === "mso_mdoc") {
				if (doctype && typeof doctype === "string") {
					return (cfg as Record<string, unknown>).doctype === doctype;
				}
			}

			if (format === "jwt_vc_json") {
				if (credentialDefinition && typeof credentialDefinition === "object") {
					const reqTypes = (credentialDefinition as { type?: string[] }).type;
					const cfgTypes = (cfg as Record<string, unknown>)
						.credential_definition as { type?: string[] } | undefined;
					if (Array.isArray(reqTypes) && Array.isArray(cfgTypes?.type)) {
						return (
							reqTypes.length === cfgTypes.type.length &&
							reqTypes.every((t) => cfgTypes.type!.includes(t))
						);
					}
				}
			}

			return true;
		}) ?? null
	);
}

type AuthorizationDetail = Record<string, unknown>;

type BearerTokenError = "invalid_token" | "insufficient_scope";

type VerifyAuthorizationParams = {
	authorizationDetails: AuthorizationDetail[];
	credentialConfigurationId: string;
	credentialIdentifier?: string;
	tokenPayload: Record<string, unknown>;
};

/**
 * Verifies that the access token is authorized for the requested credential.
 *
 * Returns an error descriptor if unauthorized, null if authorized.
 */
export function verifyCredentialAuthorization(
	params: VerifyAuthorizationParams,
): { error: BearerTokenError; errorDescription: string } | null {
	const {
		authorizationDetails,
		credentialConfigurationId,
		credentialIdentifier,
		tokenPayload,
	} = params;

	if (authorizationDetails.length) {
		const isAuthorized = authorizationDetails.some((detail) => {
			if (
				!detail ||
				typeof detail !== "object" ||
				(detail as { type?: string }).type !== "openid_credential"
			) {
				return false;
			}

			if (
				credentialIdentifier &&
				detail.credential_identifiers &&
				Array.isArray(detail.credential_identifiers) &&
				detail.credential_identifiers.includes(credentialIdentifier)
			) {
				return true;
			}

			return (
				typeof detail.credential_configuration_id === "string" &&
				detail.credential_configuration_id === credentialConfigurationId
			);
		});

		if (!isAuthorized) {
			return {
				error: "insufficient_scope",
				errorDescription: credentialIdentifier
					? "access token not authorized for requested credential identifier"
					: "access token not authorized for requested credential configuration",
			};
		}
	} else {
		const authorizedConfigId = tokenPayload.credential_configuration_id;
		if (
			typeof authorizedConfigId !== "string" ||
			authorizedConfigId !== credentialConfigurationId
		) {
			return {
				error: "insufficient_scope",
				errorDescription:
					"access token not authorized for requested credential configuration",
			};
		}
	}

	return null;
}
