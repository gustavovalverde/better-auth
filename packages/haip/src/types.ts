import type { HaipVerifierOptions } from "./vp-request";
import type { WalletAttestationOptions } from "./wallet-attestation";

export type Awaitable<T> = T | Promise<T>;

export type HaipOptions = {
	/**
	 * Advertise `require_pushed_authorization_requests`.
	 *
	 * @default true
	 */
	requirePar?: boolean;
	/**
	 * Require DPoP-bound access tokens at the oidc4vci credential endpoints.
	 * Applied to the oidc4vci plugin unless it configures `dpop` itself.
	 *
	 * @default true
	 */
	requireDpop?: boolean;
	/**
	 * JWS algorithms accepted for DPoP proofs at the oidc4vci credential
	 * endpoints. Applied the same way as `requireDpop`.
	 *
	 * @default ["ES256"]
	 */
	dpopSigningAlgorithms?: string[];
	/**
	 * PAR request_uri lifetime in seconds.
	 *
	 * @default 60
	 */
	parExpiresInSeconds?: number;
	/**
	 * VP request object lifetime in seconds.
	 *
	 * @default 300
	 */
	vpRequestExpiresInSeconds?: number;
	/**
	 * Attestation-Based Client Authentication (`attest_jwt_client_auth`).
	 * Registered only when configured; `trustedIssuers` is required.
	 */
	walletAttestation?: WalletAttestationOptions;
	/**
	 * Verifier identity for signed OpenID4VP request objects (HAIP §5.1).
	 * Required to create VP requests.
	 */
	verifier?: HaipVerifierOptions;
};
