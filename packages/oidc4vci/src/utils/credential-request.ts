type AuthorizationDetail = Record<string, unknown>;

type BearerTokenError = "invalid_token" | "insufficient_scope";

type VerifyAuthorizationParams = {
	authorizationDetails: AuthorizationDetail[];
	credentialConfigurationId: string;
	credentialIdentifier?: string;
	/** The configuration's OAuth scope, for scope-based authorization. */
	credentialScope?: string;
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
		credentialScope,
		tokenPayload,
	} = params;

	// OID4VCI 1.0 §5.1.2: a token issued for the configuration's scope
	// authorizes a credential_configuration_id request.
	if (
		credentialScope &&
		typeof tokenPayload.scope === "string" &&
		tokenPayload.scope.split(" ").includes(credentialScope)
	) {
		return null;
	}

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
