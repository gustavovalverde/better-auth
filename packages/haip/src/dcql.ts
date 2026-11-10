import type { DcqlSdJwtVcPresentation } from "dcql";
import { DcqlPresentationResult, DcqlQuery } from "dcql";

export type { DcqlQuery } from "dcql";

/**
 * A verified presentation as the oidc4vp plugin hands it to a
 * `presentationMatcher`.
 */
export type DcqlMatcherPresentation = {
	/** The DCQL credential query id the presentation answers (the `vp_token` key). */
	credentialQueryId?: string;
	/** Credential format, `dc+sd-jwt` unless stated otherwise. */
	format?: string;
	/** Disclosed claims of the credential, including `vct`. */
	claims: Record<string, unknown>;
	/** Whether the presentation carried a verified holder binding (KB-JWT). */
	holderBinding?: boolean;
	/** Issuer trust information for `trusted_authorities` matching. */
	authority?: { type: "aki"; values: [string, ...string[]] };
	[key: string]: unknown;
};

export type DcqlMatchResult<P extends DcqlMatcherPresentation> = {
	matched: boolean;
	matchedPresentations: P[];
	errors?: string[];
};

function parseQuery(raw: unknown): DcqlQuery {
	const input = typeof raw === "string" ? JSON.parse(raw) : raw;
	const query = DcqlQuery.parse(input as DcqlQuery.Input);
	DcqlQuery.validate(query);
	return query;
}

function toDcqlPresentation(
	presentation: DcqlMatcherPresentation,
): DcqlSdJwtVcPresentation {
	const format =
		presentation.format === "vc+sd-jwt" ? "vc+sd-jwt" : "dc+sd-jwt";
	const vct = presentation.claims.vct;
	return {
		credential_format: format,
		vct: typeof vct === "string" ? vct : "",
		claims: presentation.claims as DcqlSdJwtVcPresentation["claims"],
		cryptographic_holder_binding: presentation.holderBinding ?? true,
		...(presentation.authority ? { authority: presentation.authority } : {}),
	};
}

/**
 * Creates a DCQL presentation matcher backed by the `dcql` library, which
 * evaluates `credential_sets`, `claim_sets`, `multiple`, value constraints,
 * holder binding, and `trusted_authorities` as OpenID4VP 1.0 §6 defines them.
 *
 * Use it as `presentationMatcher` in the oidc4vp plugin. Presentations are
 * grouped by the credential query id they answer; a presentation without one
 * is assigned to the query when it has a single credential query.
 */
export function createDcqlMatcher() {
	return async <P extends DcqlMatcherPresentation>(input: {
		query: unknown;
		presentations: P[];
	}): Promise<DcqlMatchResult<P>> => {
		let query: DcqlQuery;
		try {
			query = parseQuery(input.query);
		} catch (error) {
			return {
				matched: false,
				matchedPresentations: [],
				errors: [
					`invalid dcql_query: ${error instanceof Error ? error.message : "parse failed"}`,
				],
			};
		}

		const onlyQueryId =
			query.credentials.length === 1 ? query.credentials[0].id : undefined;
		const grouped: Record<string, DcqlSdJwtVcPresentation[]> = {};
		const included: P[] = [];
		for (const presentation of input.presentations) {
			const queryId = presentation.credentialQueryId ?? onlyQueryId;
			if (!queryId) {
				return {
					matched: false,
					matchedPresentations: [],
					errors: [
						"presentation is not keyed by a credential query id and the query has several",
					],
				};
			}
			const entry = toDcqlPresentation(presentation);
			grouped[queryId] = [...(grouped[queryId] ?? []), entry];
			included.push(presentation);
		}

		let result: DcqlPresentationResult;
		try {
			result = DcqlPresentationResult.fromDcqlPresentation(grouped, {
				dcqlQuery: query,
			});
		} catch (error) {
			return {
				matched: false,
				matchedPresentations: [],
				errors: [
					error instanceof Error
						? error.message
						: "presentation does not match query",
				],
			};
		}

		if (result.can_be_satisfied) {
			return { matched: true, matchedPresentations: included };
		}

		const errors = query.credentials
			.filter((credentialQuery) => {
				const match = result.credential_matches[credentialQuery.id];
				return !match?.success || Boolean(match.failed_credentials);
			})
			.map(
				(credentialQuery) =>
					`no presentation satisfies credential query "${credentialQuery.id}"`,
			);
		for (const set of result.credential_sets ?? []) {
			if (set.required && !set.matching_options) {
				errors.push("a required credential set is not satisfied");
			}
		}
		return {
			matched: false,
			matchedPresentations: [],
			errors: errors.length ? errors : ["presentation does not match query"],
		};
	};
}
