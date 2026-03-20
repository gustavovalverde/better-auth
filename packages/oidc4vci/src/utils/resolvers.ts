import {
	DEFAULT_STATUS_LIST_BITS,
	DEFAULT_STATUS_LIST_ID,
	DEFAULT_STATUS_LIST_TTL_SECONDS,
} from "../constants";
import type { Oidc4vciOptions, StatusListOptions } from "../types";

export function getIssuerIdentifier(ctx: {
	context: { baseURL: string; getPlugin: (id: string) => unknown };
}) {
	const jwtPlugin = ctx.context.getPlugin("jwt") as {
		options?: { jwt?: { issuer?: string } };
	} | null;
	return jwtPlugin?.options?.jwt?.issuer ?? ctx.context.baseURL;
}

export function resolveCredentialIssuer(
	ctx: { context: { baseURL: string; getPlugin: (id: string) => unknown } },
	options: Oidc4vciOptions,
) {
	return options.credentialIssuer ?? getIssuerIdentifier(ctx);
}

export function resolveAuthorizationServers(options: Oidc4vciOptions) {
	if (options.authorizationServers?.length) {
		return options.authorizationServers;
	}
	if (options.authorizationServer) {
		return [options.authorizationServer];
	}
	return undefined;
}

export function stripTrailingSlash(value: string) {
	return value.replace(/\/+$/, "");
}

export function resolveIssuerBaseURL(
	ctx: { context: { baseURL: string } },
	options: Oidc4vciOptions,
) {
	const base = options.issuerBaseURL ?? ctx.context.baseURL;
	return stripTrailingSlash(base);
}

export function resolveCredentialEndpoint(
	ctx: { context: { baseURL: string } },
	options: Oidc4vciOptions,
) {
	return `${resolveIssuerBaseURL(ctx, options)}/oidc4vci/credential`;
}

export function resolveNonceEndpoint(
	ctx: { context: { baseURL: string } },
	options: Oidc4vciOptions,
) {
	return `${resolveIssuerBaseURL(ctx, options)}/oidc4vci/nonce`;
}

export function resolveDeferredEndpoint(
	ctx: { context: { baseURL: string } },
	options: Oidc4vciOptions,
) {
	return `${resolveIssuerBaseURL(ctx, options)}/oidc4vci/credential/deferred`;
}

export function resolveStatusListEndpoint(
	ctx: { context: { baseURL: string } },
	options: Oidc4vciOptions,
) {
	return `${resolveIssuerBaseURL(ctx, options)}/oidc4vci/status-list`;
}

export function resolveCredentialOfferUri(
	ctx: { context: { baseURL: string } },
	options: Oidc4vciOptions,
	offerId: string,
) {
	return `${resolveIssuerBaseURL(ctx, options)}/oidc4vci/credential-offer?offer_id=${offerId}`;
}

export function resolveStatusListOptions(
	options: Oidc4vciOptions,
): StatusListOptions {
	return {
		listId: options.statusList?.listId ?? DEFAULT_STATUS_LIST_ID,
		bits: options.statusList?.bits ?? DEFAULT_STATUS_LIST_BITS,
		ttlSeconds:
			options.statusList?.ttlSeconds ?? DEFAULT_STATUS_LIST_TTL_SECONDS,
	};
}

export function resolveWellKnownAliases(options: Oidc4vciOptions): string[] {
	return options.wellKnownAliases ?? [];
}

export function getStatusListUri(
	ctx: { context: { baseURL: string } },
	options: Oidc4vciOptions,
	listId: string,
) {
	const url = new URL(resolveStatusListEndpoint(ctx, options));
	if (listId !== DEFAULT_STATUS_LIST_ID) {
		url.searchParams.set("list_id", listId);
	}
	return url.toString();
}
