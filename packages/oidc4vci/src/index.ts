import type { BetterAuthPlugin } from "better-auth";
import {
	createCredentialEndpoint,
	createCredentialOfferEndpoint,
	createDeferredCredentialEndpoint,
	createGetCredentialOfferEndpoint,
	createMetadataEndpoints,
	createNonceEndpoint,
	createStatusListEndpoint,
	createUpdateCredentialStatusEndpoint,
} from "./endpoints";
import { schema } from "./schema";
import type { Oidc4vciOptions } from "./types";

declare module "@better-auth/core" {
	interface BetterAuthPluginRegistry<AuthOptions, Options> {
		oidc4vci: {
			creator: typeof oidc4vci;
		};
	}
}

export { schema } from "./schema";
export * from "./types";

export function oidc4vci(options: Oidc4vciOptions) {
	const {
		getCredentialIssuerMetadata,
		wellKnownAliasEndpoints,
		publicWellKnownEndpoints,
	} = createMetadataEndpoints(options);

	return {
		id: "oidc4vci",
		schema,
		options,
		endpoints: {
			/**
			 * OIDC4VCI Credential Issuer Metadata.
			 *
			 * NOTE: Use `auth.publicHandler` to serve this at the origin root
			 * when BetterAuth is mounted under a basePath (e.g. /api/auth).
			 */
			getCredentialIssuerMetadata,
			...wellKnownAliasEndpoints,

			/**
			 * OID4VCI nonce endpoint (Section 7).
			 *
			 * Used to obtain a `c_nonce` for proof binding.
			 */
			nonce: createNonceEndpoint(),

			/**
			 * OAuth Status List endpoint (SD-JWT VC status list).
			 */
			statusList: createStatusListEndpoint(options),

			/**
			 * Issuer-admin endpoint to create a credential offer for a user.
			 *
			 * v1: requires an authenticated session (issuer operator) to create offers.
			 */
			createCredentialOffer: createCredentialOfferEndpoint(options),

			/**
			 * OIDC4VCI credential offer URI resolution.
			 */
			getCredentialOffer: createGetCredentialOfferEndpoint(options),

			/**
			 * Issuer-admin endpoint to update credential status (revocation).
			 */
			updateCredentialStatus: createUpdateCredentialStatusEndpoint(),

			/**
			 * OIDC4VCI credential endpoint.
			 *
			 * v1: requires a JWT access token audience bound to this endpoint and a proof.jwt binding to c_nonce.
			 */
			credential: createCredentialEndpoint(options),

			/**
			 * OIDC4VCI deferred credential endpoint.
			 */
			deferredCredential: createDeferredCredentialEndpoint(options),
		},
		publicEndpoints: {
			...publicWellKnownEndpoints,
		},
	} satisfies BetterAuthPlugin;
}
