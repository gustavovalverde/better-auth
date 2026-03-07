import { createHash } from "@better-auth/utils/hash";
import {
	clientAuthenticationAnonymous,
	HashAlgorithm,
} from "@openid4vc/oauth2";
import type {
	CredentialConfigurationsSupported,
	CredentialIssuerMetadata,
	IssuerMetadataResult,
} from "@openid4vc/openid4vci";
import { Openid4vciIssuer, Openid4vciVersion } from "@openid4vc/openid4vci";
import { createAuthEndpoint } from "better-auth/api";
import {
	SUPPORTED_PROOF_ALGS,
	WELL_KNOWN_CREDENTIAL_ISSUER_PATH,
} from "../constants";
import type { Oidc4vciOptions } from "../types";
import {
	resolveAuthorizationServers,
	resolveCredentialEndpoint,
	resolveCredentialIssuer,
	resolveDeferredEndpoint,
	resolveNonceEndpoint,
	resolvePublicWellKnownPaths,
	resolveWellKnownAliases,
} from "../utils/resolvers";

let openid4vciIssuerInstance: Openid4vciIssuer | null = null;

const HASH_ALGORITHM_MAP: Record<
	HashAlgorithm,
	"SHA-256" | "SHA-384" | "SHA-512"
> = {
	[HashAlgorithm.Sha256]: "SHA-256",
	[HashAlgorithm.Sha384]: "SHA-384",
	[HashAlgorithm.Sha512]: "SHA-512",
};

export function getOpenid4vciIssuer() {
	if (openid4vciIssuerInstance) return openid4vciIssuerInstance;
	openid4vciIssuerInstance = new Openid4vciIssuer({
		callbacks: {
			hash: async (data, alg) => {
				const algorithm = HASH_ALGORITHM_MAP[alg] ?? "SHA-256";
				const hash = await createHash(algorithm).digest(data);
				return new Uint8Array(hash);
			},
			signJwt: async () => {
				throw new Error("signJwt not configured for oidc4vci validation");
			},
			verifyJwt: async () => ({ verified: false }),
			generateRandom: async (byteLength) => {
				const buffer = new Uint8Array(byteLength);
				crypto.getRandomValues(buffer);
				return buffer;
			},
			clientAuthentication: clientAuthenticationAnonymous(),
		},
	});
	return openid4vciIssuerInstance;
}

export function buildCredentialConfigurations(
	options: Oidc4vciOptions,
): CredentialConfigurationsSupported {
	const configurations: CredentialConfigurationsSupported = {};
	const SD_JWT_FORMATS = new Set(["dc+sd-jwt", "vc+sd-jwt"]);
	for (const cfg of options.credentialConfigurations) {
		const format = cfg.format ?? "dc+sd-jwt";
		configurations[cfg.id] = {
			format,
			...(SD_JWT_FORMATS.has(format) ? { vct: cfg.vct } : {}),
			cryptographic_binding_methods_supported: ["jwk"],
			proof_types_supported: {
				jwt: {
					proof_signing_alg_values_supported: [...SUPPORTED_PROOF_ALGS],
				},
			},
		};
	}
	return configurations;
}

export function buildIssuerMetadata(
	ctx: { context: { baseURL: string; getPlugin: (id: string) => unknown } },
	options: Oidc4vciOptions,
): CredentialIssuerMetadata {
	const issuerIdentifier = resolveCredentialIssuer(ctx, options);
	const credentialEndpoint = resolveCredentialEndpoint(ctx, options);
	const nonceEndpoint = resolveNonceEndpoint(ctx, options);
	const deferredEndpoint =
		typeof options.deferredIssuance?.shouldDefer === "function"
			? resolveDeferredEndpoint(ctx, options)
			: undefined;
	const authorizationServers = resolveAuthorizationServers(options);
	return {
		credential_issuer: issuerIdentifier,
		credential_endpoint: credentialEndpoint,
		nonce_endpoint: nonceEndpoint,
		...(deferredEndpoint
			? { deferred_credential_endpoint: deferredEndpoint }
			: {}),
		...(authorizationServers
			? { authorization_servers: authorizationServers }
			: {}),
		credential_configurations_supported: buildCredentialConfigurations(options),
	};
}

export function buildIssuerMetadataResult(
	ctx: { context: { baseURL: string; getPlugin: (id: string) => unknown } },
	options: Oidc4vciOptions,
): IssuerMetadataResult {
	const credentialIssuer = buildIssuerMetadata(ctx, options);
	const openid4vciIssuer = getOpenid4vciIssuer();
	const knownCredentialConfigurations =
		openid4vciIssuer.getKnownCredentialConfigurationsSupported(
			credentialIssuer,
		);
	return {
		originalDraftVersion: Openid4vciVersion.V1,
		credentialIssuer,
		authorizationServers: [],
		knownCredentialConfigurations,
	};
}

export function createMetadataEndpoints(options: Oidc4vciOptions) {
	const wellKnownAliases = resolveWellKnownAliases(options).filter(
		(path) => path !== WELL_KNOWN_CREDENTIAL_ISSUER_PATH,
	);
	const wellKnownAliasEndpoints = Object.fromEntries(
		wellKnownAliases.map((path, index) => [
			`credentialIssuerMetadataAlias${index}`,
			createAuthEndpoint(
				path,
				{
					method: "GET",
				},
				async (ctx) => ctx.json(buildIssuerMetadata(ctx, options)),
			),
		]),
	);

	const publicWellKnownPaths = resolvePublicWellKnownPaths(options);
	const publicWellKnownEndpoints = Object.fromEntries(
		publicWellKnownPaths.map((path, index) => [
			index === 0
				? "publicCredentialIssuerMetadata"
				: `publicCredentialIssuerMetadataAlias${index}`,
			createAuthEndpoint(
				path,
				{
					method: "GET",
				},
				async (ctx) => ctx.json(buildIssuerMetadata(ctx, options)),
			),
		]),
	);

	const getCredentialIssuerMetadata = createAuthEndpoint(
		WELL_KNOWN_CREDENTIAL_ISSUER_PATH,
		{
			method: "GET",
		},
		async (ctx) => {
			return ctx.json(buildIssuerMetadata(ctx, options));
		},
	);

	return {
		getCredentialIssuerMetadata,
		wellKnownAliasEndpoints,
		publicWellKnownEndpoints,
	};
}
