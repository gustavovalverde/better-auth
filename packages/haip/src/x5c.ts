import { X509Certificate } from "node:crypto";
import { base64 } from "@better-auth/utils/base64";
import type { JWK } from "jose";
import { base64url } from "jose";
import type { Awaitable } from "./types";

const PEM_BLOCK =
	/-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----/;

/**
 * Normalizes a certificate given as PEM or base64 DER to the base64 DER form
 * that the JOSE `x5c` header carries (RFC 7515 §4.1.6).
 */
export function toX5cEntry(certificate: string): string {
	const pem = PEM_BLOCK.exec(certificate);
	const body = pem ? pem[1]! : certificate;
	return body.replace(/\s+/g, "");
}

function decodeDer(entry: string) {
	return base64.decode(toX5cEntry(entry));
}

/** The public key of a certificate (PEM or base64 DER) as a JWK. */
export function certificatePublicJwk(certificate: string): JWK {
	return parseCertificate(certificate).publicKey.export({
		format: "jwk",
	}) as JWK;
}

function parseCertificate(entry: string): X509Certificate {
	return new X509Certificate(decodeDer(entry));
}

/**
 * Computes the OpenID4VP `x509_hash` Client Identifier Prefix value: the
 * base64url SHA-256 digest of the DER-encoded leaf certificate (OID4VP 1.0
 * §5.9.3). The full Client Identifier is `x509_hash:<value>`.
 */
export async function computeX509Hash(leafCertificate: string) {
	const digest = await crypto.subtle.digest(
		"SHA-256",
		decodeDer(leafCertificate),
	);
	return base64url.encode(new Uint8Array(digest));
}

function isWithinValidity(certificate: X509Certificate, now: Date) {
	return (
		now >= new Date(certificate.validFrom) &&
		now <= new Date(certificate.validTo)
	);
}

function issuedBy(child: X509Certificate, issuer: X509Certificate) {
	return child.checkIssued(issuer) && child.verify(issuer.publicKey);
}

/**
 * Validates an `x5c` chain (leaf first) against configured trust anchors.
 *
 * The path is built from the leaf through the certificates in `x5c` until a
 * certificate is issued by, or is identical to, a trust anchor. Every
 * certificate on the path must be within its validity period, and every issuing
 * certificate must be a CA. A chain whose root is not a configured anchor is
 * rejected, so a self-signed certificate in the header never establishes trust.
 *
 * Returns the leaf certificate and the anchor that terminated the path.
 */
export function validateCertificateChain(
	x5c: readonly string[],
	trustAnchors: readonly string[],
	now: Date = new Date(),
): { leaf: X509Certificate; anchor: X509Certificate } {
	if (!x5c.length) {
		throw new Error("x5c chain is empty");
	}
	if (!trustAnchors.length) {
		throw new Error("no trust anchors configured");
	}
	const chain = x5c.map(parseCertificate);
	const anchors = trustAnchors.map(parseCertificate);
	const leaf = chain[0]!;

	let current = leaf;
	const visited = new Set<string>();
	for (let depth = 0; depth <= chain.length; depth++) {
		if (!isWithinValidity(current, now)) {
			throw new Error(
				"certificate in x5c chain is outside its validity period",
			);
		}
		if (visited.has(current.fingerprint256)) {
			throw new Error("x5c chain contains a loop");
		}
		visited.add(current.fingerprint256);

		const pinned = anchors.find(
			(anchor) => anchor.fingerprint256 === current.fingerprint256,
		);
		if (pinned) {
			return { leaf, anchor: pinned };
		}
		const anchor = anchors.find((candidate) => issuedBy(current, candidate));
		if (anchor) {
			if (!anchor.ca) {
				throw new Error("trust anchor is not a CA certificate");
			}
			if (!isWithinValidity(anchor, now)) {
				throw new Error("trust anchor is outside its validity period");
			}
			return { leaf, anchor };
		}
		const next = chain.find(
			(candidate) =>
				candidate !== current &&
				!visited.has(candidate.fingerprint256) &&
				issuedBy(current, candidate),
		);
		if (!next) break;
		if (!next.ca) {
			throw new Error("intermediate certificate is not a CA certificate");
		}
		current = next;
	}
	throw new Error("x5c chain does not lead to a trusted anchor");
}

/**
 * Creates a `resolveCredentialHeaders` callback that adds x5c certificate chain
 * headers to SD-JWT VCs and status list JWTs.
 *
 * HAIP requires the issuer's X.509 certificate chain in the protected header
 * so verifiers can validate the credential against a PKI trust anchor.
 * Certificates may be given as PEM or base64 DER; the header carries DER.
 */
export function createX5cHeaders(
	x5c: string[],
): () => Awaitable<Record<string, unknown>> {
	const entries = x5c.map(toX5cEntry);
	return () => ({ x5c: entries });
}
