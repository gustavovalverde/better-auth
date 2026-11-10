import { BetterAuthError } from "@better-auth/core/error";
import { getJwks } from "@better-auth/core/oauth2";
import { isLoopbackHost } from "@better-auth/core/utils/host";
import type {
	JSONWebKeySet,
	JWK,
	JWTPayload,
	JWTVerifyResult,
	ProtectedHeaderParameters,
} from "jose";
import {
	createLocalJWKSet,
	decodeJwt,
	decodeProtectedHeader,
	importJWK,
	jwtVerify,
} from "jose";
import { validateCertificateChain } from "./x5c";

/**
 * An issuer whose signatures the plugin trusts, identified by key material the
 * deployment configures. A JWT is trusted only when it verifies against one of
 * these keys; claims inside the JWT (`iss`, header `jwk`) never establish
 * trust on their own.
 */
export type TrustedIssuer = {
	/**
	 * Expected `iss` claim. When set and the JWT carries `iss`, they must match.
	 * Client Attestation JWTs from draft 08 onward omit `iss`, so a JWT without
	 * `iss` is matched by key alone.
	 */
	issuer?: string;
	/** The issuer's public signing keys. */
	jwks?: JSONWebKeySet;
	/**
	 * HTTPS URL of the issuer's JWK Set. Fetched with Better Auth's
	 * redirect-refusing, cached JWKS loader.
	 */
	jwksUri?: string;
	/**
	 * X.509 trust anchors (PEM or base64 DER). A JWT whose header carries `x5c`
	 * must chain to one of them.
	 */
	trustAnchors?: string[];
};

export type TrustedJwtOptions = {
	trustedIssuers: TrustedIssuer[];
	/** Accepted `typ` values, compared without the `application/` prefix. */
	types: readonly string[];
	/** Accepted JWS algorithms. */
	algorithms: readonly string[];
	clockToleranceSeconds?: number;
	now?: Date;
};

export type TrustedJwtResult = {
	payload: JWTPayload;
	protectedHeader: ProtectedHeaderParameters;
	trustedIssuer: TrustedIssuer;
};

function normalizeTyp(typ: string | undefined) {
	return typ?.toLowerCase().replace(/^application\//, "");
}

/**
 * Validates trusted issuer configuration at setup time so a misconfiguration
 * fails loudly instead of rejecting every request at runtime.
 */
export function assertTrustedIssuers(
	label: string,
	trustedIssuers: TrustedIssuer[] | undefined,
): asserts trustedIssuers is TrustedIssuer[] {
	if (!trustedIssuers?.length) {
		throw new BetterAuthError(
			`${label} requires at least one trusted issuer with jwks, jwksUri, or trustAnchors`,
		);
	}
	for (const issuer of trustedIssuers) {
		if (!issuer.jwks && !issuer.jwksUri && !issuer.trustAnchors?.length) {
			throw new BetterAuthError(
				`${label}: trusted issuer ${issuer.issuer ?? "(unnamed)"} must configure jwks, jwksUri, or trustAnchors`,
			);
		}
		if (issuer.jwksUri) {
			let url: URL;
			try {
				url = new URL(issuer.jwksUri);
			} catch {
				throw new BetterAuthError(
					`${label}: jwksUri is not a valid URL: ${issuer.jwksUri}`,
				);
			}
			const loopbackHttp =
				url.protocol === "http:" && isLoopbackHost(url.hostname);
			if (url.protocol !== "https:" && !loopbackHttp) {
				throw new BetterAuthError(
					`${label}: jwksUri must use https: ${issuer.jwksUri}`,
				);
			}
		}
	}
}

function issuerMatches(trusted: TrustedIssuer, iss: unknown) {
	return !trusted.issuer || iss === undefined || trusted.issuer === iss;
}

/**
 * Verifies a JWT against configured issuer keys.
 *
 * A header `jwk`, `jku`, or `x5u` is rejected: those carry key material chosen
 * by the presenter. A header `x5c` chain must lead to a configured trust anchor,
 * and the JWT must verify with the chain's leaf key. Otherwise the JWT must
 * verify against a configured JWK Set.
 */
export async function verifyTrustedJwt(
	jwt: string,
	options: TrustedJwtOptions,
): Promise<TrustedJwtResult> {
	let header: ProtectedHeaderParameters;
	let unverified: JWTPayload;
	try {
		header = decodeProtectedHeader(jwt);
		unverified = decodeJwt(jwt);
	} catch {
		throw new Error("malformed JWT");
	}
	if (header.jwk || header.jku || header.x5u) {
		throw new Error(
			"JWT header key material (jwk, jku, x5u) is not trusted; the issuer key must be configured",
		);
	}
	const alg = header.alg;
	if (
		!alg ||
		alg === "none" ||
		alg.startsWith("HS") ||
		!options.algorithms.includes(alg)
	) {
		throw new Error(`unsupported JWT algorithm: ${alg ?? "none"}`);
	}
	if (!options.types.includes(normalizeTyp(header.typ) ?? "")) {
		throw new Error(`unexpected JWT typ: ${header.typ ?? "(missing)"}`);
	}

	const verifyOptions = {
		algorithms: [...options.algorithms],
		clockTolerance: options.clockToleranceSeconds ?? 0,
		...(options.now ? { currentDate: options.now } : {}),
	};
	const candidates = options.trustedIssuers.filter((trusted) =>
		issuerMatches(trusted, unverified.iss),
	);

	if (header.x5c?.length) {
		for (const trusted of candidates) {
			if (!trusted.trustAnchors?.length) continue;
			let leafJwk: JWK;
			try {
				const { leaf } = validateCertificateChain(
					header.x5c,
					trusted.trustAnchors,
					options.now,
				);
				leafJwk = leaf.publicKey.export({ format: "jwk" }) as JWK;
			} catch {
				continue;
			}
			const key = await importJWK(leafJwk, alg);
			const result: JWTVerifyResult = await jwtVerify(jwt, key, verifyOptions);
			return { ...result, trustedIssuer: trusted };
		}
	}

	let lastError: unknown;
	for (const trusted of candidates) {
		const jwks = trusted.jwks
			? trusted.jwks
			: trusted.jwksUri
				? await getJwks(jwt, { jwksFetch: trusted.jwksUri })
				: undefined;
		if (!jwks) continue;
		try {
			const result = await jwtVerify(
				jwt,
				createLocalJWKSet(jwks),
				verifyOptions,
			);
			return { ...result, trustedIssuer: trusted };
		} catch (error) {
			lastError = error;
		}
	}
	if (lastError instanceof Error && lastError.name.startsWith("JWT")) {
		// A claim check (exp, nbf) failed after a trusted key verified the
		// signature: report it rather than masking it as an untrusted issuer.
		throw lastError;
	}
	// A JWT carrying x5c may still verify against a configured JWK Set above;
	// reaching here means neither its chain nor a configured key trusted it.
	throw new Error(
		header.x5c?.length
			? "x5c chain is not issued by a trusted issuer"
			: "JWT is not signed by a trusted issuer",
	);
}
