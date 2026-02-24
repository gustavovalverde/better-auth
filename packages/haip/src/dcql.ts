export type DcqlCredentialQuery = {
	id: string;
	format: string;
	meta?: { vct_values?: string[] };
	claims?: DcqlClaimQuery[];
};

export type DcqlClaimQuery = {
	path: string[];
	values?: unknown[];
};

export type DcqlQuery = {
	credentials: DcqlCredentialQuery[];
};

type VerifiedPresentation = {
	issuer?: string;
	subject?: string;
	claims: Record<string, unknown>;
	status?: number;
};

type MatchResult = {
	matched: boolean;
	matchedPresentations: VerifiedPresentation[];
	errors?: string[];
};

/**
 * Creates a DCQL presentation matcher.
 *
 * Used as `presentationMatcher` in oidc4vp config.
 */
export function createDcqlMatcher() {
	return async (input: {
		query: unknown;
		presentations: VerifiedPresentation[];
	}): Promise<MatchResult> => {
		const query = parseDcqlQuery(input.query);
		if (!query) {
			return {
				matched: false,
				matchedPresentations: [],
				errors: ["invalid dcql_query"],
			};
		}

		const matched: VerifiedPresentation[] = [];
		const errors: string[] = [];

		for (const credQuery of query.credentials) {
			const match = findMatchingPresentation(
				credQuery,
				input.presentations,
				matched,
			);
			if (match) {
				matched.push(match);
			} else {
				errors.push(
					`no presentation matches credential query "${credQuery.id}"`,
				);
			}
		}

		if (errors.length) {
			return { matched: false, matchedPresentations: matched, errors };
		}
		return { matched: true, matchedPresentations: matched };
	};
}

function parseDcqlQuery(raw: unknown): DcqlQuery | null {
	if (typeof raw === "string") {
		try {
			raw = JSON.parse(raw);
		} catch {
			return null;
		}
	}
	if (
		!raw ||
		typeof raw !== "object" ||
		!Array.isArray((raw as DcqlQuery).credentials)
	) {
		return null;
	}
	return raw as DcqlQuery;
}

function findMatchingPresentation(
	credQuery: DcqlCredentialQuery,
	presentations: VerifiedPresentation[],
	alreadyMatched: VerifiedPresentation[],
): VerifiedPresentation | null {
	for (const pres of presentations) {
		if (alreadyMatched.includes(pres)) continue;

		// Check VCT match if meta.vct_values is specified
		if (credQuery.meta?.vct_values?.length) {
			const vct = pres.claims.vct;
			if (typeof vct !== "string" || !credQuery.meta.vct_values.includes(vct)) {
				continue;
			}
		}

		// Check required claims are present
		if (credQuery.claims?.length) {
			const allClaimsPresent = credQuery.claims.every((claimQuery) =>
				matchesClaim(pres.claims, claimQuery),
			);
			if (!allClaimsPresent) continue;
		}

		return pres;
	}
	return null;
}

function matchesClaim(
	claims: Record<string, unknown>,
	claimQuery: DcqlClaimQuery,
): boolean {
	let value: unknown = claims;
	for (const segment of claimQuery.path) {
		if (value == null || typeof value !== "object") return false;
		value = (value as Record<string, unknown>)[segment];
	}
	if (value === undefined) return false;

	// If specific values are required, check membership
	if (claimQuery.values?.length) {
		return claimQuery.values.includes(value);
	}
	return true;
}

/**
 * Helper to build a DCQL query from credential queries.
 */
export function buildDcqlQuery(credentials: DcqlCredentialQuery[]): DcqlQuery {
	return { credentials };
}
