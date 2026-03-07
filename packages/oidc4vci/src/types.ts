import type { User } from "better-auth/types";

export type Awaitable<T> = T | Promise<T>;

export type StoreTokenType =
	| "access_token"
	| "refresh_token"
	| "authorization_code"
	| "pre_authorized_code"
	| "tx_code"
	| "c_nonce"
	| "credential_identifier"
	| "transaction_id";

export type StoreTokens =
	| "hashed"
	| { hash: (token: string, type: StoreTokenType) => Awaitable<string> };

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
	| "unsupported_credential_format"
	| "invalid_proof"
	| "invalid_nonce"
	| "invalid_transaction_id"
	| "credential_request_denied"
	| "issuance_pending";

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
	 *
	 * These are served via the public handler (root) and kept as basePath aliases
	 * for backwards compatibility.
	 */
	wellKnownAliases?: string[];
	/**
	 * Optional JWKS URL for validating access tokens when the issuer is separate
	 * from the authorization server.
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
	 * OIDC4VCI allows omitting client authentication for the pre-authorized code flow,
	 * but BetterAuth still issues JWT access tokens with an `azp`/client context.
	 *
	 * v1: if you don't provide this, `createCredentialOffer` must pass `client_id`.
	 */
	defaultWalletClientId?: string;
	/**
	 * Credential configurations supported by this issuer.
	 *
	 * v1: keep to a simple list; each configuration maps to a single SD-JWT VC "vct".
	 */
	credentialConfigurations: {
		id: string;
		vct: string;
		format?: Oidc4vciCredentialFormat;
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
	 * Access token audience used for the credential endpoint.
	 *
	 * v1 defaults to `${issuerBaseURL}/oidc4vci/credential` (issuerBaseURL defaults to BetterAuth baseURL).
	 */
	credentialAudience?: string;
	/**
	 * SD-JWT VC lifetime (seconds).
	 *
	 * @default 31536000 (365d)
	 */
	credentialExpiresInSeconds?: number;
	/**
	 * If enabled, the credential endpoint will accept an `access_token` in the request body
	 * when the Authorization header isn't available (useful for some RPC/test clients).
	 *
	 * Default is strict OID4VCI behavior: Authorization header only.
	 */
	allowAccessTokenInBody?: boolean;
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
		 * Return false to respond with `issuance_pending`.
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
	 * signature. When provided, the built-in `node:crypto` signer is bypassed entirely.
	 *
	 * Required for algorithms not supported by Node.js (e.g. ML-DSA-65).
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
	 * Validate the access token beyond standard JWT verification.
	 *
	 * Called after successful JWT verification. Use this to enforce sender-constrained
	 * tokens (e.g., DPoP binding verification). Throw to reject the request.
	 *
	 * @example
	 * ```ts
	 * accessTokenValidator: createDpopAccessTokenValidator()
	 * ```
	 */
	accessTokenValidator?: (input: {
		request: Request;
		tokenPayload: Record<string, unknown>;
	}) => Awaitable<void>;
	/**
	 * Custom proof type validators for the credential endpoint.
	 *
	 * Keys are proof_type values (e.g. "attestation"). The built-in "jwt" handler
	 * is always available and does not need to be registered here.
	 *
	 * Each validator receives the raw proof object and must return a JWK thumbprint
	 * (jkt) for the holder binding, plus the c_nonce used in the proof.
	 */
	proofValidators?: Record<
		string,
		(input: {
			proof: Record<string, unknown>;
			nonce: string;
			audience: string;
			userId?: string;
			clientId?: string;
		}) => Awaitable<ProofValidationResult>
	>;
};

export type CredentialConfiguration =
	Oidc4vciOptions["credentialConfigurations"][number];

export type ProofValidationResult = {
	/** JWK thumbprint for the cnf binding */
	jkt: string;
	/** c_nonce used in the proof (for nonce validation) */
	cNonce: string;
	/** Additional cnf claims beyond jkt */
	extraCnf?: Record<string, unknown>;
};
