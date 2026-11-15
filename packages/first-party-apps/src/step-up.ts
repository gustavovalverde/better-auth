import type { GenericEndpointContext } from "@better-auth/core";
import { BetterAuthError } from "@better-auth/core/error";
import type { OAuthOptions, Scope } from "@better-auth/oauth-provider";
import { getOAuthProviderApi } from "@better-auth/oauth-provider";
import { toResourceList } from "@better-auth/oauth-provider/internal";
import { NO_STORE_HEADERS } from "better-auth/api";
import type { GrantCeiling } from "./auth-session";
import {
	AUTH_SESSION_MODEL,
	createAuthSession,
	findLiveSession,
	rotateAuthSessionHandle,
	rowExpiry,
} from "./auth-session";
import {
	challengeError,
	FIRST_PARTY_APPS_ERROR_CODES as ERRORS,
} from "./error-codes";
import type {
	FirstPartyAuthorizationRequest,
	FirstPartyAuthSession,
	FirstPartyClient,
	FirstPartyStepUpInput,
	ResolvedFirstPartyAppsOptions,
} from "./types";

/**
 * Refuses a token request with HTTP 403 `insufficient_authorization` and an
 * `auth_session` the client presents at the Authorization Challenge Endpoint
 * to step up (draft §6.2). Resolves without side effects when the client
 * cannot finish a step-up there; the caller then sends its own refusal.
 *
 * Call it only on a path that refuses the token request: it verifies the
 * request's client and DPoP proof, which the token endpoint would otherwise
 * verify again and reject as replayed.
 */
export async function challengeFirstPartyStepUp(
	ctx: GenericEndpointContext,
	input: FirstPartyStepUpInput,
): Promise<void> {
	const plugin = ctx.context.getPlugin("first-party-apps");
	if (!plugin) {
		throw new BetterAuthError(
			"challengeFirstPartyStepUp requires the first-party-apps plugin.",
		);
	}
	const options = plugin.options as ResolvedFirstPartyAppsOptions;
	const oauthOptions = ctx.context.getPlugin("oauth-provider")!
		.options as OAuthOptions<Scope[]>;
	const provider = getOAuthProviderApi(ctx, oauthOptions);

	const client = await provider.getClient(input.clientId);
	if (!client || client.disabled || !allowsAuthorizationCode(client)) return;
	if (!(await options.isFirstPartyClient({ client, ctx }))) return;
	const live = input.sessionId
		? await findLiveSession(ctx, input.sessionId)
		: null;
	const session = live?.session.userId === input.userId ? live.session : null;
	// A row without a session lets anyone who holds its handle start a
	// challenge for the grant's user, so it needs a holder the server can
	// recognize: a confidential client or the grant's DPoP key.
	if (
		!session &&
		input.dpopJkt === null &&
		client.tokenEndpointAuthMethod === "none"
	) {
		return;
	}

	await provider.authenticateClient({
		clientId: input.clientId,
		requireCredentials: false,
	});
	const proof = await provider.verifyDpopProof(
		input.dpopJkt !== null
			? { expectedJkt: input.dpopJkt }
			: {
					required:
						options.requireDpop || client.dpopBoundAccessTokens === true,
				},
	);
	const dpopJkt = input.dpopJkt ?? proof?.jkt ?? null;

	const ceiling: GrantCeiling = {
		scope: input.request.scope,
		...(toResourceList(input.request.resource)
			? { resource: toResourceList(input.request.resource) }
			: {}),
		...(input.request.claims !== undefined
			? { claims: input.request.claims }
			: {}),
	};
	const request: FirstPartyAuthorizationRequest = Object.fromEntries(
		Object.entries(input.request).filter(([, value]) => value !== undefined),
	);
	const existing = await findStepUpRow(ctx, {
		clientId: input.clientId,
		userId: input.userId,
		sessionId: session?.id ?? null,
		dpopJkt,
	});
	const rowFields = {
		request: JSON.stringify(request),
		ceiling: JSON.stringify(ceiling),
		method: null,
		methodState: null,
	};
	const handle = existing
		? await rotateAuthSessionHandle(ctx, existing.id, rowFields)
		: (
				await createAuthSession(ctx, {
					...rowFields,
					clientId: input.clientId,
					userId: input.userId,
					sessionId: session?.id ?? null,
					ownsSession: false,
					dpopJkt,
					state: session ? "authenticated" : "pending",
					amr: null,
					expiresAt: rowExpiry(options, {
						sessionExpiresAt: session?.expiresAt,
						bound: dpopJkt !== null,
					}),
				})
			).handle;

	challengeError(
		"FORBIDDEN",
		"insufficient_authorization",
		input.description ?? ERRORS.STEP_UP_REQUIRED.message,
		{ ...input.fields, auth_session: handle },
		responseHeaders(ctx),
	);
}

function allowsAuthorizationCode(client: FirstPartyClient): boolean {
	return client.grantTypes?.length
		? client.grantTypes.includes("authorization_code")
		: true;
}

/** C4: one row per client, user, session, and DPoP key. */
async function findStepUpRow(
	ctx: GenericEndpointContext,
	key: {
		clientId: string;
		userId: string;
		sessionId: string | null;
		dpopJkt: string | null;
	},
): Promise<FirstPartyAuthSession | null> {
	const rows = await ctx.context.adapter.findMany<FirstPartyAuthSession>({
		model: AUTH_SESSION_MODEL,
		where: key.sessionId
			? [{ field: "sessionId", value: key.sessionId }]
			: [{ field: "userId", value: key.userId }],
	});
	const now = new Date();
	return (
		rows.find(
			(row) =>
				row.clientId === key.clientId &&
				row.userId === key.userId &&
				(row.sessionId ?? null) === key.sessionId &&
				(row.dpopJkt ?? null) === key.dpopJkt &&
				row.ceiling &&
				new Date(row.expiresAt) > now,
		) ?? null
	);
}

/**
 * The headers this request accumulated, such as the next `DPoP-Nonce`. A
 * before hook writes them to the dispatch context, which an error thrown
 * from the hook does not carry by itself.
 */
function responseHeaders(ctx: GenericEndpointContext): Headers {
	const headers = new Headers(NO_STORE_HEADERS);
	const sources = [
		(ctx.context as { responseHeaders?: Headers }).responseHeaders,
		ctx.responseHeaders,
	];
	for (const source of sources) {
		source?.forEach((value, name) => {
			headers.set(name, value);
		});
	}
	return headers;
}
