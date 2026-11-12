import type { GenericEndpointContext } from "@better-auth/core";
import type {
	OAuthProviderApi,
	StoreTokenType,
} from "@better-auth/oauth-provider";
import { getOAuthProviderApi } from "@better-auth/oauth-provider";
import { APIError } from "better-auth/api";

/**
 * The oauth-provider capability surface for this request. Issuer state (offer
 * codes, `c_nonce`, credential identifiers, transaction ids) is keyed by the
 * provider's own token hash so it follows the provider's `storeTokens` policy.
 */
export function getProviderApi(ctx: GenericEndpointContext): OAuthProviderApi {
	const provider = ctx.context.getPlugin("oauth-provider");
	if (!provider) {
		throw new APIError("INTERNAL_SERVER_ERROR", {
			error: "server_error",
			error_description: "oidc4vci requires the oauth-provider plugin",
		});
	}
	return getOAuthProviderApi(ctx, provider.options);
}

export async function hashIssuerToken(
	ctx: GenericEndpointContext,
	token: string,
	type: StoreTokenType,
) {
	return getProviderApi(ctx).hashToken(token, type);
}
