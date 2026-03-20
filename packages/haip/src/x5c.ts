import type { Awaitable } from "./types";

/**
 * Creates a `resolveCredentialHeaders` callback that adds x5c certificate chain
 * headers to SD-JWT VCs and status list JWTs.
 *
 * HAIP requires the issuer's X.509 certificate chain in the protected header
 * so verifiers can validate the credential against a PKI trust anchor.
 */
export function createX5cHeaders(
	x5c: string[],
): () => Awaitable<Record<string, unknown>> {
	return () => ({ x5c });
}
