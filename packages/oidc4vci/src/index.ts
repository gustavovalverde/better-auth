import { extendOAuthProvider } from "@better-auth/oauth-provider";
import type { BetterAuthPlugin } from "better-auth";
import { createCredentialEndpoint } from "./endpoints/credential";
import { createDeferredCredentialEndpoint } from "./endpoints/deferred";
import { createMetadataEndpoints } from "./endpoints/metadata";
import { createNonceEndpoint } from "./endpoints/nonce";
import {
	createCredentialOfferEndpoint,
	createGetCredentialOfferEndpoint,
} from "./endpoints/offer";
import {
	createStatusListEndpoint,
	createUpdateCredentialStatusEndpoint,
} from "./endpoints/status";
import {
	createPreAuthorizedCodeHandler,
	PRE_AUTH_GRANT_TYPE,
} from "./grant-handler";
import { schema } from "./schema";
import type { Oidc4vciOptions } from "./types";

declare module "@better-auth/core" {
	interface BetterAuthPluginRegistry<AuthOptions, Options> {
		oidc4vci: {
			creator: typeof oidc4vci;
		};
	}
}

export { PRE_AUTH_GRANT_TYPE } from "./grant-handler";
export { schema } from "./schema";
export type * from "./types";

export function oidc4vci(options: Oidc4vciOptions) {
	const { getCredentialIssuerMetadata, wellKnownAliasEndpoints } =
		createMetadataEndpoints(options);

	return {
		id: "oidc4vci",
		schema,
		options,
		init(ctx) {
			// The pre-authorized_code grant requires oauth-provider. A metadata-only
			// deployment (no oauth-provider) still serves the issuer well-known
			// documents, so register the grant only when the provider is present.
			if (!ctx.getPlugin("oauth-provider")) {
				return;
			}
			extendOAuthProvider(ctx, {
				grants: {
					[PRE_AUTH_GRANT_TYPE]: createPreAuthorizedCodeHandler(),
				},
			});
		},
		endpoints: {
			/**
			 * OIDC4VCI Credential Issuer Metadata.
			 *
			 * Serve this at `/.well-known/openid-credential-issuer` via your
			 * framework's routing (e.g. a Next.js route file) when BetterAuth
			 * is mounted under a basePath (e.g. /api/auth).
			 */
			getCredentialIssuerMetadata,
			...wellKnownAliasEndpoints,

			/**
			 * OID4VCI nonce endpoint (§7), the only source of `c_nonce` values
			 * for proofs.
			 */
			nonce: createNonceEndpoint(),

			/**
			 * OAuth Status List endpoint (SD-JWT VC status list).
			 */
			statusList: createStatusListEndpoint(options),

			/**
			 * Creates a pre-authorized code credential offer. Requires a session;
			 * offers about another user require `authorizeCredentialOffer`.
			 */
			createCredentialOffer: createCredentialOfferEndpoint(options),

			/**
			 * OIDC4VCI credential offer URI resolution.
			 */
			getCredentialOffer: createGetCredentialOfferEndpoint(options),

			/**
			 * Updates credential status (revocation). Holders may revoke their own
			 * credentials; anything else requires `authorizeCredentialStatusUpdate`.
			 */
			updateCredentialStatus: createUpdateCredentialStatusEndpoint(options),

			/**
			 * OID4VCI credential endpoint (§8). Requires a JWT access token for
			 * this endpoint, its DPoP proof when the token is bound, and one proof
			 * of possession bound to a `c_nonce`.
			 */
			credential: createCredentialEndpoint(options),

			/**
			 * OIDC4VCI deferred credential endpoint.
			 */
			deferredCredential: createDeferredCredentialEndpoint(options),
		},
		rateLimit: [
			{
				pathMatcher: (path: string) =>
					path === "/oidc4vci/nonce" || path === "/oidc4vci/credential-offer",
				window: 60,
				max: 30,
			},
		],
	} satisfies BetterAuthPlugin;
}
