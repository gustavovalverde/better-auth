import type { GenericEndpointContext } from "@better-auth/core";
import type { Session, User } from "better-auth/types";
import type { JWK } from "jose";

export type Awaitable<T> = T | Promise<T>;

export type SdJwtDisclosureFrame = {
	_sd?: string[];
	_sd_decoy?: number;
	[key: string]: unknown;
};

export type JwkRecord = {
	id: string;
	publicKey: string;
	privateKey: string;
	createdAt: Date;
	alg?: string | null;
	crv?: string | null;
	expiresAt?: Date | null;
};

export type Oidc4vciCredentialFormat =
	| "dc+sd-jwt"
	| "vc+sd-jwt"
	| "mso_mdoc"
	| "jwt_vc_json";

export type Oidc4vciCredentialErrorCode =
	| "invalid_credential_request"
	| "unknown_credential_configuration"
	| "unknown_credential_identifier"
	| "invalid_proof"
	| "invalid_nonce"
	| "invalid_transaction_id"
	| "credential_request_denied";

export type RequestedClaim = {
	name: string;
	mandatory: boolean;
};

export type ResolveClaimsInput = {
	user: User;
	credentialConfigurationId: string;
	credentialIdentifier?: string;
	requestedClaims?: RequestedClaim[] | null;
};

export type StatusListOptions = {
	listId: string;
	bits: 1 | 2 | 4 | 8;
	ttlSeconds: number;
};

export type ProofValidationResult = {
	/** Public key the issued credential is bound to (`cnf.jwk`). */
	jwk: JWK;
	/** The `c_nonce` the proof is bound to. */
	cNonce: string;
	/** Additional `cnf` members beyond `jwk`. */
	extraCnf?: Record<string, unknown>;
};

export type ProofValidator = (input: {
	/** The proof value from `proofs[<proof_type>][0]` (a compact JWT for `attestation`). */
	proof: unknown;
	proofType: string;
	/** The Credential Issuer Identifier, the expected proof audience. */
	audience: string;
	userId?: string;
	clientId?: string;
}) => Awaitable<ProofValidationResult>;

export type CredentialOfferAuthorizationInput = {
	session: { session: Session; user: User };
	/** The user the credential would describe. */
	userId: string;
	credentialConfigurationId: string;
	clientId: string;
	ctx: GenericEndpointContext;
};

export type CredentialStatusAuthorizationInput = {
	session: { session: Session; user: User };
	credential: { id: string; userId: string; status: number };
	status: number;
	ctx: GenericEndpointContext;
};

export type Oidc4vciOptions = {
	/**
	 * Credential Issuer Identifier (issuer URL used in metadata).
	 *
	 * Defaults to the JWT issuer (if configured) or BetterAuth baseURL.
	 */
	credentialIssuer?: string;
	/**
	 * Base URL for issuer endpoints (credential, nonce, offer, status list).
	 *
	 * Use this when the issuer service is hosted separately from the OAuth AS.
	 * Defaults to BetterAuth baseURL.
	 */
	issuerBaseURL?: string;
	/**
	 * OAuth Authorization Servers issuing access tokens for this Credential Issuer.
	 *
	 * If omitted, wallets assume the credential_issuer is also the authorization server.
	 */
	authorizationServers?: string[];
	/**
	 * Convenience alias for a single authorization server URL.
	 */
	authorizationServer?: string;
	/**
	 * Additional well-known paths (root-relative) to serve issuer metadata from.
	 */
	wellKnownAliases?: string[];
	/**
	 * Optional JWKS URL for validating access tokens when the issuer is separate
	 * from the authorization server. Fetched with Better Auth's
	 * redirect-refusing, cached JWKS loader.
	 */
	accessTokenJwksUrl?: string;
	/**
	 * Override access token issuer for JWT validation.
	 */
	accessTokenIssuer?: string;
	/**
	 * Override access token audience for JWT validation.
	 */
	accessTokenAudience?: string;
	/**
	 * Default OAuth client id to associate with offers.
	 *
	 * If you don't provide this, `createCredentialOffer` must pass `client_id`.
	 */
	defaultWalletClientId?: string;
	/**
	 * Credential configurations supported by this issuer. Each configuration
	 * maps to a single SD-JWT VC `vct`.
	 */
	credentialConfigurations: {
		id: string;
		vct: string;
		format?: Oidc4vciCredentialFormat;
		/** OAuth scope that requests this configuration (OID4VCI 1.0 §12.2.4). */
		scope?: string;
		sdJwt?: {
			/**
			 * Top-level claims to make selectively disclosable.
			 * Defaults to ["name", "email", "email_verified"] when omitted.
			 * Set to [] to disable selective disclosure.
			 */
			disclosures?: string[];
			/**
			 * Number of decoy digests to add to the SD list.
			 *
			 * @default 0
			 */
			decoyCount?: number;
		};
	}[];
	/**
	 * Resolve claim values to include in the issued SD-JWT VC.
	 *
	 * When omitted, defaults to the user profile (name, email, email_verified).
	 */
	resolveClaims?: (
		input: ResolveClaimsInput,
	) => Awaitable<Record<string, unknown>>;
	/**
	 * Decides whether the signed-in user may create a credential offer.
	 * Offers carry a pre-authorized code that redeems a credential about
	 * `userId`, so the default allows only offers about the signed-in user.
	 */
	authorizeCredentialOffer?: (
		input: CredentialOfferAuthorizationInput,
	) => Awaitable<boolean>;
	/**
	 * Decides whether the signed-in user may change a credential's status.
	 * The default lets a holder revoke (status other than 0) their own
	 * credentials; restoring a credential to valid requires this callback.
	 */
	authorizeCredentialStatusUpdate?: (
		input: CredentialStatusAuthorizationInput,
	) => Awaitable<boolean>;
	/**
	 * Access token audience used for the credential endpoint.
	 *
	 * Defaults to `${issuerBaseURL}/oidc4vci/credential` (issuerBaseURL defaults to BetterAuth baseURL).
	 */
	credentialAudience?: string;
	/**
	 * SD-JWT VC lifetime (seconds).
	 *
	 * @default 31536000 (365d)
	 */
	credentialExpiresInSeconds?: number;
	/**
	 * If enabled, the credential endpoint accepts an `access_token` in the
	 * request body when the Authorization header isn't available. Body tokens
	 * are treated as bearer tokens, so DPoP-bound tokens cannot use it.
	 */
	allowAccessTokenInBody?: boolean;
	/**
	 * DPoP (RFC 9449) policy for the credential and deferred credential
	 * endpoints. A DPoP-bound access token is always checked for a valid proof.
	 */
	dpop?: {
		/**
		 * Reject access tokens that are not DPoP-bound.
		 *
		 * @default false
		 */
		required?: boolean;
		/**
		 * JWS algorithms accepted for DPoP proofs. Defaults to the
		 * oauth-provider `dpop.signingAlgorithms`, else Better Auth core's list.
		 */
		signingAlgorithms?: readonly string[];
		/** Maximum DPoP proof age in seconds. */
		proofMaxAgeSeconds?: number;
	};
	/**
	 * Maximum age of a `jwt` proof, measured from its `iat`.
	 *
	 * @default 300
	 */
	proofMaxAgeSeconds?: number;
	/**
	 * Status list configuration (OAuth Status List for SD-JWT VC).
	 */
	statusList?: {
		/**
		 * Identifier for the status list (single issuer default is "default").
		 */
		listId?: string;
		/**
		 * Bits per status entry.
		 *
		 * @default 1
		 */
		bits?: 1 | 2 | 4 | 8;
		/**
		 * Time-to-live for the status list JWT (seconds).
		 *
		 * @default 3600
		 */
		ttlSeconds?: number;
	};
	/**
	 * Deferred issuance configuration.
	 * When enabled, the issuer may return a transaction_id and issue later via the
	 * deferred credential endpoint.
	 */
	deferredIssuance?: {
		/**
		 * Decide whether to defer issuance for a given request.
		 * If omitted, deferred issuance is disabled.
		 */
		shouldDefer?: (input: {
			credentialConfigurationId: string;
			userId: string;
			clientId?: string;
		}) => Awaitable<boolean>;
		/**
		 * Check if a deferred credential is ready for issuance.
		 * When omitted, the deferred endpoint always issues immediately.
		 * Return false to tell the wallet to poll again after `interval`.
		 */
		isReady?: (input: {
			credentialConfigurationId: string;
			userId: string;
			clientId?: string;
		}) => Awaitable<boolean>;
		/**
		 * Minimum wait time (seconds) to suggest to the wallet before polling.
		 *
		 * @default 3600
		 */
		intervalSeconds?: number;
		/**
		 * How long the transaction_id is valid for (seconds).
		 *
		 * @default 3600
		 */
		transactionExpiresInSeconds?: number;
	};
	/**
	 * Custom raw signer for SD-JWT VC issuance.
	 *
	 * Receives the compact `header.payload` string and must return the base64url-encoded
	 * signature. When provided, the built-in signer is bypassed entirely.
	 *
	 * Required for algorithms the platform's Web Crypto does not support (e.g. ML-DSA-65).
	 */
	credentialSigner?: (data: string) => Awaitable<string>;
	/**
	 * Resolve additional protected headers for issued SD-JWT VCs and status list JWTs.
	 *
	 * Use this to add x5c certificate chains, custom kid overrides, etc.
	 * The returned record is spread into the JWT protected header alongside
	 * the default { kid, typ } fields.
	 */
	resolveCredentialHeaders?: (input: {
		kid: string;
		alg: string;
		format: string;
		credentialConfigurationId: string;
	}) => Awaitable<Record<string, unknown>>;
	/**
	 * Additional access token checks, run after JWT verification and DPoP
	 * enforcement. Throw to reject the request.
	 */
	accessTokenValidator?: (input: {
		request: Request;
		tokenPayload: Record<string, unknown>;
	}) => Awaitable<void>;
	/**
	 * Validators for proof types other than `jwt`, keyed by proof type (for
	 * example `attestation`). The built-in `jwt` validator is always available.
	 * Each validator returns the key the credential is bound to and the
	 * `c_nonce` the proof carries.
	 */
	proofValidators?: Record<string, ProofValidator>;
};

export type CredentialConfiguration =
	Oidc4vciOptions["credentialConfigurations"][number];
