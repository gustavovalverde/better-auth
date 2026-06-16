import { APIError } from "better-auth/api";
import type { Oidc4vciCredentialErrorCode } from "./types";

export function setNoStore(ctx: any) {
	ctx?.responseHeaders?.set("Cache-Control", "no-store");
	ctx?.responseHeaders?.set("Pragma", "no-cache");
}

export function throwOidc4vciCredentialError(
	error: Oidc4vciCredentialErrorCode,
	errorDescription?: string,
	extra?: Record<string, unknown>,
): never {
	throw new APIError(
		"BAD_REQUEST",
		{
			error,
			...(errorDescription ? { error_description: errorDescription } : {}),
			...extra,
		},
		{
			"Cache-Control": "no-store",
			Pragma: "no-cache",
		},
	);
}

export function throwBearerTokenError(input: {
	status: "UNAUTHORIZED" | "FORBIDDEN";
	error: "invalid_token" | "insufficient_scope";
	errorDescription?: string;
	headers?: HeadersInit;
}): never {
	const safeDescription = input.errorDescription?.replaceAll('"', "'");
	const wwwAuthenticateParts = [
		`Bearer error="${input.error}"`,
		safeDescription ? `error_description="${safeDescription}"` : undefined,
	].filter(Boolean);

	throw new APIError(
		input.status,
		{
			error: input.error,
			...(input.errorDescription
				? { error_description: input.errorDescription }
				: {}),
		},
		{
			"Cache-Control": "no-store",
			Pragma: "no-cache",
			"WWW-Authenticate": wwwAuthenticateParts.join(", "),
			...input.headers,
		},
	);
}
