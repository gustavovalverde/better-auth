import type { AuthContext, GenericEndpointContext } from "@better-auth/core";
import { getCurrentAuthEndpointContext } from "@better-auth/core/context";
import { BetterAuthError } from "@better-auth/core/error";
import type {
	OAuthOptions,
	OAuthProviderExtension,
	Scope,
	VerificationValue,
} from "@better-auth/oauth-provider";
import { extendOAuthProvider } from "@better-auth/oauth-provider";
import { getAuthEndpointUrl } from "@better-auth/oauth-provider/internal";
import type { BetterAuthPlugin } from "better-auth";
import { mergeSchema } from "better-auth/db";
import { AUTH_SESSION_MODEL, rotateAuthSessionHandle } from "./auth-session";
import {
	AUTHORIZE_CHALLENGE_PATH,
	createAuthorizeChallengeEndpoint,
	OWNED_PARAMETERS,
} from "./endpoint";
import { FIRST_PARTY_APPS_ERROR_CODES } from "./error-codes";
import { schema } from "./schema";
import type {
	FirstPartyAppsOptions,
	FirstPartyAuthSession,
	ResolvedFirstPartyAppsOptions,
} from "./types";

declare module "@better-auth/core" {
	interface BetterAuthPluginRegistry<AuthOptions, Options> {
		"first-party-apps": {
			creator: typeof firstPartyApps;
		};
	}
}

export { FIRST_PARTY_APPS_ERROR_CODES } from "./error-codes";
export { passwordMethod } from "./password";
export { schema } from "./schema";
export { challengeFirstPartyStepUp } from "./step-up";
export type {
	FirstPartyAppsOptions,
	FirstPartyAppsSchemaOptions,
	FirstPartyAuthorizationDecision,
	FirstPartyAuthorizationPolicyInput,
	FirstPartyAuthorizationRequest,
	FirstPartyAuthSession,
	FirstPartyClient,
	FirstPartyMethod,
	FirstPartyMethodRespondInput,
	FirstPartyMethodRespondResult,
	FirstPartyMethodStartInput,
	FirstPartyMethodStartResult,
	FirstPartySessionFieldsInput,
	FirstPartyStepUpInput,
} from "./types";

const TOKEN_RESPONSE_COMPOSED = Symbol.for(
	"better-auth.first-party-apps.token-response",
);

/**
 * The Authorization Challenge Endpoint of OAuth 2.0 for First-Party
 * Applications for `oauthProvider()`: a native or command-line app your
 * organization ships signs a user in without a browser redirect, through
 * pluggable credential methods, and redeems the code at the token endpoint.
 *
 * Requires the `oauth-provider` plugin with the `authorization_code` grant.
 *
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-first-party-apps-04
 */
export function firstPartyApps(options: FirstPartyAppsOptions) {
	const resolved = resolveOptions(options);
	const extension: OAuthProviderExtension = {
		name: "first-party-apps",
		// Draft §8.
		metadata: ({ ctx }) => ({
			authorization_challenge_endpoint: getAuthEndpointUrl(
				ctx,
				AUTHORIZE_CHALLENGE_PATH,
			),
		}),
	};
	return {
		id: "first-party-apps",
		options: resolved,
		// `mergeSchema` applies overrides in place, so merge into a copy.
		schema: mergeSchema(structuredClone(schema), options.schema),
		init(ctx) {
			const provider = ctx.getPlugin("oauth-provider");
			if (!provider) {
				throw new BetterAuthError(
					'@better-auth/first-party-apps requires the "oauth-provider" plugin. Add it to your plugins array.',
				);
			}
			const oauthOptions = provider.options as OAuthOptions<Scope[]>;
			if (
				oauthOptions.grantTypes &&
				!oauthOptions.grantTypes.includes("authorization_code")
			) {
				throw new BetterAuthError(
					"@better-auth/first-party-apps requires the authorization_code grant in oauthProvider({ grantTypes }).",
				);
			}
			for (const method of resolved.methods) method.init?.(ctx);
			warnOnInsecureBaseURL(ctx);
			extendOAuthProvider(ctx, extension);
			composeTokenResponse(ctx, oauthOptions);
		},
		endpoints: {
			authorizeChallenge: createAuthorizeChallengeEndpoint(resolved),
		},
		rateLimit: [
			{
				pathMatcher: (path: string) => path === AUTHORIZE_CHALLENGE_PATH,
				window: resolved.rateLimit.window,
				max: resolved.rateLimit.max,
			},
		],
		$ERROR_CODES: FIRST_PARTY_APPS_ERROR_CODES,
	} satisfies BetterAuthPlugin;
}

function resolveOptions(
	options: FirstPartyAppsOptions,
): ResolvedFirstPartyAppsOptions {
	if (typeof options?.isFirstPartyClient !== "function") {
		throw new BetterAuthError(
			"@better-auth/first-party-apps requires an `isFirstPartyClient` function.",
		);
	}
	if (!options.methods?.length) {
		throw new BetterAuthError(
			"@better-auth/first-party-apps requires at least one method.",
		);
	}
	const ids = new Set<string>();
	const responseParameters = new Map<string, string>();
	for (const method of options.methods) {
		if (ids.has(method.id)) {
			throw new BetterAuthError(
				`@better-auth/first-party-apps: duplicate method id "${method.id}".`,
			);
		}
		ids.add(method.id);
		if (!method.responseParameters.length) {
			throw new BetterAuthError(
				`@better-auth/first-party-apps: method "${method.id}" needs at least one response parameter.`,
			);
		}
		for (const name of method.responseParameters) {
			if (OWNED_PARAMETERS.has(name)) {
				throw new BetterAuthError(
					`@better-auth/first-party-apps: method "${method.id}" cannot use the plugin's "${name}" parameter as a response parameter.`,
				);
			}
			const owner = responseParameters.get(name);
			if (owner) {
				throw new BetterAuthError(
					`@better-auth/first-party-apps: methods "${owner}" and "${method.id}" both use the response parameter "${name}".`,
				);
			}
			responseParameters.set(name, method.id);
		}
	}
	const budget = options.failureBudget;
	return {
		isFirstPartyClient: options.isFirstPartyClient,
		methods: options.methods,
		authorizationPolicy: options.authorizationPolicy,
		requireDpop: options.requireDpop ?? false,
		session: {
			expiresIn: options.session?.expiresIn,
			fields: options.session?.fields,
		},
		authSession: {
			expiresIn: options.authSession?.expiresIn ?? 600,
			maxFailures: options.authSession?.maxFailures ?? 3,
			maxRequests: options.authSession?.maxRequests ?? 20,
		},
		failureBudget:
			budget === false
				? false
				: {
						maxFailures: budget?.maxFailures ?? 10,
						window: budget?.window ?? 900,
					},
		rateLimit: {
			window: options.rateLimit?.window ?? 60,
			max: options.rateLimit?.max ?? 10,
		},
	};
}

/**
 * Adds a fresh `auth_session` to the authorization-code grant's token
 * response when a DPoP-bound row exists for the code's client, session, and
 * key (draft §6.1). The provider has no extension point for this response,
 * so the plugin composes the app's `customTokenResponseFields`, which the
 * token endpoint reads from the provider's options on every request.
 */
function composeTokenResponse(
	ctx: AuthContext,
	oauthOptions: OAuthOptions<Scope[]>,
): void {
	const appFields = oauthOptions.customTokenResponseFields;
	if (
		appFields &&
		(appFields as { [TOKEN_RESPONSE_COMPOSED]?: true })[TOKEN_RESPONSE_COMPOSED]
	) {
		return;
	}
	let warned = false;
	const composed: NonNullable<
		OAuthOptions<Scope[]>["customTokenResponseFields"]
	> = async (info) => {
		const { auth_session: appValue, ...fields } = appFields
			? await appFields(info)
			: {};
		if (appValue !== undefined && !warned) {
			warned = true;
			ctx.logger.warn(
				"@better-auth/first-party-apps owns the auth_session token response field; the value from customTokenResponseFields is ignored.",
			);
		}
		if (info.grantType !== "authorization_code" || !info.verificationValue) {
			return fields;
		}
		const handle = await rotateHandleForCode(info.verificationValue);
		return handle ? { ...fields, auth_session: handle } : fields;
	};
	Object.defineProperty(composed, TOKEN_RESPONSE_COMPOSED, { value: true });
	oauthOptions.customTokenResponseFields = composed;
}

/**
 * The provider has verified the token request's proof against the code and
 * consumed the code when it builds the response, so the new handle goes to
 * the holder of the row's key.
 */
async function rotateHandleForCode(
	verificationValue: VerificationValue,
): Promise<string | null> {
	const jkt = verificationValue.query.dpop_jkt;
	if (!jkt || !verificationValue.sessionId) return null;
	const ctx = getCurrentAuthEndpointContext() as GenericEndpointContext;
	if (!ctx.context.getPlugin("first-party-apps")) return null;
	const rows = await ctx.context.adapter.findMany<FirstPartyAuthSession>({
		model: AUTH_SESSION_MODEL,
		where: [{ field: "sessionId", value: verificationValue.sessionId }],
	});
	const now = new Date();
	const row = rows.find(
		(candidate) =>
			candidate.state === "authenticated" &&
			candidate.clientId === verificationValue.query.client_id &&
			candidate.dpopJkt === jkt &&
			new Date(candidate.expiresAt) > now,
	);
	return row ? rotateAuthSessionHandle(ctx, row.id) : null;
}

/** Draft §4.1: the endpoint must use `https`. */
function warnOnInsecureBaseURL(ctx: AuthContext): void {
	let url: URL;
	try {
		url = new URL(ctx.baseURL);
	} catch {
		return;
	}
	const loopback = ["localhost", "127.0.0.1", "[::1]"];
	if (url.protocol === "http:" && !loopback.includes(url.hostname)) {
		ctx.logger.warn(
			"@better-auth/first-party-apps: the authorization challenge endpoint must be served over https (draft §4.1). Use an https baseURL in production.",
		);
	}
}
