export const SUPPORTED_PROOF_ALGS = [
	"EdDSA",
	"ES256",
	"ES256K",
	"ES384",
	"ES512",
	"RS256",
	"PS256",
] as const;

export const DEFAULT_SD_DISCLOSURES = [
	"name",
	"email",
	"email_verified",
] as const;

export const SD_HASH_ALG = "sha-256";

export const DEFAULT_STATUS_LIST_ID = "default";
export const DEFAULT_STATUS_LIST_BITS = 1 as const;
export const DEFAULT_STATUS_LIST_TTL_SECONDS = 3600;

export const WELL_KNOWN_CREDENTIAL_ISSUER_PATH =
	"/.well-known/openid-credential-issuer";

export const VERIFICATION_TYPES = {
	C_NONCE: "oidc4vci_c_nonce",
	PRE_AUTH_CODE: "pre_authorized_code",
	CREDENTIAL_IDENTIFIER: "oidc4vci_credential_identifier",
	DEFERRED_CREDENTIAL: "oidc4vci_deferred_credential",
} as const;
