import type { User } from "better-auth/types";
import type {
	Oidc4vciOptions,
	RequestedClaim,
	ResolveClaimsInput,
} from "../types";

export function resolveRequestedClaims(
	authorizationDetails: Record<string, unknown>[],
	input: {
		credentialConfigurationId: string;
		credentialIdentifier?: string;
	},
) {
	if (!authorizationDetails.length) return null;
	const claimMap = new Map<string, boolean>();

	for (const detail of authorizationDetails) {
		if (
			!detail ||
			typeof detail !== "object" ||
			(detail as { type?: string }).type !== "openid_credential"
		) {
			continue;
		}
		const typed = detail;
		const credentialIdentifiers = Array.isArray(typed.credential_identifiers)
			? (typed.credential_identifiers as string[])
			: [];

		const matchesCredential =
			(input.credentialIdentifier &&
				credentialIdentifiers.includes(input.credentialIdentifier)) ||
			typed.credential_configuration_id === input.credentialConfigurationId;

		if (!matchesCredential) continue;

		const claims = Array.isArray(typed.claims)
			? (typed.claims as Record<string, unknown>[])
			: [];
		for (const claim of claims) {
			if (!claim || typeof claim !== "object") continue;
			const path = (claim as { path?: unknown }).path;
			if (
				!Array.isArray(path) ||
				!path.length ||
				!path.every((segment) => typeof segment === "string")
			) {
				continue;
			}
			if (path.length !== 1) continue;
			const name = path[0]!;
			const mandatory = (claim as { mandatory?: unknown }).mandatory === true;
			claimMap.set(name, claimMap.get(name) === true ? true : mandatory);
		}
	}

	if (!claimMap.size) return null;
	return Array.from(claimMap.entries()).map(([name, mandatory]) => ({
		name,
		mandatory,
	}));
}

export function filterClaimsForRequest(
	claims: Record<string, unknown>,
	requestedClaims?: RequestedClaim[] | null,
) {
	if (!requestedClaims) {
		return { claims, missingMandatory: [] as string[] };
	}
	const filtered: Record<string, unknown> = {};
	const missingMandatory: string[] = [];
	for (const requested of requestedClaims) {
		if (
			Object.hasOwn(claims, requested.name) &&
			claims[requested.name] !== undefined
		) {
			filtered[requested.name] = claims[requested.name];
		} else if (requested.mandatory) {
			missingMandatory.push(requested.name);
		}
	}
	return { claims: filtered, missingMandatory };
}

export function extractDefaultClaims(user: User) {
	return {
		name: user.name,
		email: user.email,
		email_verified: user.emailVerified,
	};
}

export async function resolveClaimsForUser(
	options: Oidc4vciOptions,
	input: ResolveClaimsInput,
) {
	if (typeof options.resolveClaims === "function") {
		const resolved = await options.resolveClaims(input);
		if (resolved && typeof resolved === "object") {
			return resolved;
		}
		return {};
	}
	return extractDefaultClaims(input.user);
}
