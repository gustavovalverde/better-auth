import { defineErrorCodes } from "@better-auth/core/utils/error-codes";
import { APIError } from "better-auth/api";

/** Error descriptions for the Authorization Challenge Endpoint (draft §5.2.2). */
export const FIRST_PARTY_APPS_ERROR_CODES = defineErrorCodes({
	FORM_ENCODING_REQUIRED:
		"The initial request must use application/x-www-form-urlencoded",
	RESPONSE_TYPE_REQUIRED: "response_type is required",
	UNSUPPORTED_RESPONSE_TYPE: "response_type must be code",
	REQUEST_URI_NOT_ACCEPTED: "request_uri is not accepted at this endpoint",
	REQUEST_OBJECT_NOT_SUPPORTED: "request object not supported",
	REDIRECT_URI_NOT_ACCEPTED:
		"redirect_uri is not accepted: the authorization code is returned directly",
	CREDENTIAL_BEFORE_CHALLENGE:
		"A credential can only answer a challenge from an auth_session",
	UNEXPECTED_PARAMETERS:
		"Authorization request parameters cannot change while a challenge is waiting for a response",
	RESPONSE_REQUIRED: "The request must answer the pending challenge",
	LOGIN_REQUIRED: "The user must sign in",
	BROWSER_REQUIRED: "The user must continue in the browser",
	NOT_FIRST_PARTY:
		"The client may not use the authorization challenge endpoint",
	INVALID_SESSION: "The auth_session is invalid, expired, or already in use",
	CLIENT_MISMATCH: "client_id does not match the auth_session",
	DPOP_NOT_EXPECTED: "The auth_session is not bound to a DPoP key",
	AUTHENTICATION_FAILED: "The credential is not valid",
	ACCOUNT_CANNOT_SIGN_IN: "The account cannot sign in",
	SCOPE_EXCEEDS_GRANT: "The requested scope exceeds the grant",
	RESOURCE_EXCEEDS_GRANT: "The requested resource exceeds the grant",
	CLAIMS_EXCEED_GRANT: "The claims request cannot change for this grant",
	STEP_UP_REQUIRED: "Additional authorization is required",
});

// Draft §5.2.2: error_description is limited to %x20-21 / %x23-5B / %x5D-7E.
const FORBIDDEN_DESCRIPTION_CHARACTERS = /[^\x20\x21\x23-\x5B\x5D-\x7E]/g;

function sanitizeDescription(
	description: string | undefined,
): string | undefined {
	if (description === undefined) return undefined;
	const sanitized = description.replace(FORBIDDEN_DESCRIPTION_CHARACTERS, "");
	return sanitized || undefined;
}

type ErrorStatus = "BAD_REQUEST" | "FORBIDDEN";

/** Throws a draft §5.2.2 error response. Fields are top-level JSON members. */
export function challengeError(
	status: ErrorStatus,
	error: string,
	description?: string,
	fields?: Record<string, unknown>,
	headers?: Record<string, string> | Headers,
): never {
	const errorDescription = sanitizeDescription(description);
	throw new APIError(
		status,
		{
			...fields,
			error,
			...(errorDescription ? { error_description: errorDescription } : {}),
		},
		headers,
	);
}

export function invalidRequest(description: string): never {
	return challengeError("BAD_REQUEST", "invalid_request", description);
}

export function invalidSession(): never {
	return challengeError(
		"BAD_REQUEST",
		"invalid_session",
		FIRST_PARTY_APPS_ERROR_CODES.INVALID_SESSION.message,
	);
}
