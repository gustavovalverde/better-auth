export type Awaitable<T> = T | Promise<T>;

export type HaipOptions = {
	/** X.509 certificate chain (PEM strings, leaf first) */
	x5c?: string[];
	/** Require Pushed Authorization Requests. Default: true */
	requirePar?: boolean;
	/** Require DPoP sender-constrained tokens. Default: true */
	requireDpop?: boolean;
	/** Allowed DPoP signing algorithms. Default: ["ES256"] */
	dpopSigningAlgValues?: string[];
	/** PAR request_uri lifetime in seconds. Default: 60 */
	parExpiresInSeconds?: number;
	/** VP authorization request lifetime in seconds. Default: 300 */
	vpRequestExpiresInSeconds?: number;
	/** Wallet attestation strategy options */
	walletAttestation?: {
		trustedIssuers?: string[];
	};
};
