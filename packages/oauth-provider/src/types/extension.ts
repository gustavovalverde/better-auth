import type { Awaitable, GenericEndpointContext } from "@better-auth/core";
import type { User } from "better-auth/types";
import type { ClientAuthResult, OAuthOptions, SchemaClient, Scope } from ".";

/**
 * Handler for a custom grant type registered via the extension protocol.
 *
 * Return the same shape as `createUserTokens` (a token response object).
 * The framework serializes the return value as JSON automatically.
 */
export type GrantTypeHandler = (
	ctx: GenericEndpointContext,
	opts: OAuthOptions<Scope[]>,
) => Promise<unknown>;

/**
 * Context provided to token claim contributors.
 */
export type TokenClaimInfo = {
	user: User & Record<string, unknown>;
	scopes: string[];
	client: SchemaClient<Scope[]>;
	referenceId?: string;
};

/**
 * Input for a client authentication strategy contributed by an extension.
 */
export type ClientAuthStrategyInput = {
	assertion: string;
	assertionType: string;
	clientId?: string;
	headers: Headers;
	ctx: GenericEndpointContext;
	opts: OAuthOptions<Scope[]>;
};

/**
 * Extension contract for plugins that extend oauth-provider.
 *
 * Plugins contribute to this contract via the `extensions` field:
 * ```ts
 * {
 *   id: "my-plugin",
 *   extensions: {
 *     "oauth-provider": {
 *       grantTypes: { "urn:custom:grant": myHandler },
 *       grantTypeURIs: ["urn:custom:grant"],
 *     } satisfies OAuthProviderExtension,
 *   },
 * }
 * ```
 */
export interface OAuthProviderExtension {
	/**
	 * Custom grant type handlers.
	 * Key is the full grant_type URI string.
	 */
	grantTypes?: Record<string, GrantTypeHandler>;

	/**
	 * Grant type URIs to add to the allowlist and advertise
	 * in grant_types_supported metadata.
	 */
	grantTypeURIs?: string[];

	/**
	 * Contribute fields to OAuth/OIDC discovery metadata.
	 * Called at request time in the discovery endpoint handlers.
	 *
	 * Use this for non-array fields (endpoint URLs, capability flags).
	 * Array fields like grant_types_supported are handled via
	 * grantTypeURIs and tokenEndpointAuthMethods.
	 */
	metadata?: (ctx: { baseURL: string }) => Record<string, unknown>;

	/**
	 * Contribute claims to tokens at creation time.
	 * Called per-request during token issuance, BEFORE the user's
	 * customAccessTokenClaims / customIdTokenClaims.
	 */
	tokenClaims?: {
		access?: (info: TokenClaimInfo) => Awaitable<Record<string, unknown>>;
		id?: (info: TokenClaimInfo) => Awaitable<Record<string, unknown>>;
	};

	/**
	 * Additional token endpoint authentication methods to advertise
	 * in token_endpoint_auth_methods_supported.
	 */
	tokenEndpointAuthMethods?: string[];

	/**
	 * Custom client authentication strategies for the token endpoint.
	 *
	 * Keys are `client_assertion_type` URNs. When a matching assertion type
	 * arrives at the token endpoint, the strategy is called instead of
	 * the built-in client_secret_basic/client_secret_post path.
	 *
	 * Strategies from multiple extensions are merged. If two extensions
	 * register the same assertion type, the last one wins.
	 * User-level `OAuthOptions.clientAuthStrategies` always takes precedence.
	 */
	clientAuthStrategies?: Record<
		string,
		(input: ClientAuthStrategyInput) => Promise<ClientAuthResult>
	>;
}
