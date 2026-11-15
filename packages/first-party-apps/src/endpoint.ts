import type { GenericEndpointContext } from "@better-auth/core";
import type { Session, User } from "@better-auth/core/db";
import type {
	OAuthOptions,
	OAuthProviderApi,
	Scope,
} from "@better-auth/oauth-provider";
import { getOAuthProviderApi } from "@better-auth/oauth-provider";
import {
	createOAuthEndpoint,
	parseScopes,
	toResourceList,
} from "@better-auth/oauth-provider/internal";
import { isAPIError } from "better-auth/api";
import * as z from "zod";
import type { MethodState } from "./auth-session";
import {
	claimAuthSession,
	createAuthSession,
	deleteAuthSession,
	endAuthSession,
	findAuthSession,
	findLiveSession,
	openMethodState,
	readCeiling,
	readRequest,
	rowExpiry,
	sealMethodState,
	updateAuthSession,
} from "./auth-session";
import {
	challengeError,
	FIRST_PARTY_APPS_ERROR_CODES as ERRORS,
	invalidRequest,
	invalidSession,
} from "./error-codes";
import {
	getBudgetKey,
	releaseBudgetFailure,
	reserveBudgetFailure,
} from "./failure-budget";
import type {
	FirstPartyAuthorizationDecision,
	FirstPartyAuthorizationRequest,
	FirstPartyAuthSession,
	FirstPartyClient,
	FirstPartyMethod,
	FirstPartyMethodRespondResult,
	FirstPartyMethodStartResult,
	ResolvedFirstPartyAppsOptions,
} from "./types";

export const AUTHORIZE_CHALLENGE_PATH = "/oauth2/authorize-challenge";

/**
 * Parameters the plugin owns. Everything else in a request reaches methods
 * as `params`, and no method may claim one of these as a response parameter.
 */
export const OWNED_PARAMETERS: ReadonlySet<string> = new Set([
	"client_id",
	"client_secret",
	"client_assertion",
	"client_assertion_type",
	"response_type",
	"response_mode",
	"auth_session",
	"login_hint",
	"id_token_hint",
	"scope",
	"resource",
	"claims",
	"acr_values",
	"max_age",
	"prompt",
	"nonce",
	"code_challenge",
	"code_challenge_method",
	"ui_locales",
	"display",
	"state",
	"redirect_uri",
	"request",
	"request_uri",
	"dpop_jkt",
	"grant_type",
	"code",
	"code_verifier",
	"refresh_token",
]);

/** Parameters that describe the grant. A later request replaces them. */
const GRANT_PARAMETERS = [
	"scope",
	"resource",
	"claims",
	"acr_values",
	"ui_locales",
] as const;
/** Parameters that apply to one code, removed once a code used them. */
const ONE_TIME_PARAMETERS = [
	"code_challenge",
	"code_challenge_method",
	"nonce",
	"prompt",
	"max_age",
] as const;
const AUTHORIZATION_PARAMETERS = [...GRANT_PARAMETERS, ...ONE_TIME_PARAMETERS];

/** Response members the plugin owns; a method's challenge cannot set them. */
const OWNED_RESPONSE_FIELDS = new Set([
	"error",
	"error_description",
	"auth_session",
	"challenge_type",
]);

/** Prompts that need a page, which only the browser flow can show. */
const PAGE_PROMPTS = new Set(["consent", "select_account", "create"]);

/**
 * Client authentication methods whose credentials can be checked twice in
 * one request. A client assertion is single-use, so for any other method the
 * plugin leaves client authentication to `issueAuthorizationCode` on a
 * request that can end in a code.
 */
const REPEATABLE_AUTH_METHODS = new Set([
	"none",
	"client_secret_basic",
	"client_secret_post",
]);

const RESERVED_SESSION_FIELDS = new Set([
	"id",
	"token",
	"userId",
	"expiresAt",
	"createdAt",
	"updatedAt",
]);

const optionalString = z.string().optional();

const bodySchema = z.looseObject({
	client_id: optionalString,
	response_type: optionalString,
	auth_session: optionalString,
	login_hint: optionalString,
	scope: optionalString,
	resource: z.union([z.string(), z.array(z.string())]).optional(),
	claims: optionalString,
	acr_values: optionalString,
	max_age: z.coerce.number().int().nonnegative().optional(),
	prompt: optionalString,
	nonce: optionalString,
	code_challenge: optionalString,
	code_challenge_method: optionalString,
	ui_locales: optionalString,
	redirect_uri: optionalString,
	request: optionalString,
	request_uri: optionalString,
});

type Body = z.infer<typeof bodySchema>;

/** The state of one request to the endpoint. */
interface Exchange {
	ctx: GenericEndpointContext;
	options: ResolvedFirstPartyAppsOptions;
	oauthOptions: OAuthOptions<Scope[]>;
	provider: OAuthProviderApi;
	body: Body;
	/** Whether this request's client was authenticated. */
	clientVerified: boolean;
	/**
	 * The budget key holding this request's reserved failure, until a failed
	 * response spends it. Any other outcome gives it back.
	 */
	budgetReservation: string | null;
}

/** The 200 response (draft §5.2.1). Every other answer is thrown. */
type CodeResponse = { authorization_code: string };

type LiveSession = {
	session: Session & Record<string, unknown>;
	user: User & Record<string, unknown>;
};

export function createAuthorizeChallengeEndpoint(
	options: ResolvedFirstPartyAppsOptions,
) {
	return createOAuthEndpoint(
		AUTHORIZE_CHALLENGE_PATH,
		{
			method: "POST",
			body: bodySchema,
			formParams: { repeatable: ["resource"] },
			metadata: {
				noStore: true,
				allowedMediaTypes: [
					"application/x-www-form-urlencoded",
					"application/json",
				],
				openapi: {
					description:
						"Authorization Challenge Endpoint (draft-ietf-oauth-first-party-apps §5)",
				},
			},
		},
		async (ctx) => {
			const oauthOptions = ctx.context.getPlugin("oauth-provider")!
				.options as OAuthOptions<Scope[]>;
			const exchange: Exchange = {
				ctx,
				options,
				oauthOptions,
				provider: getOAuthProviderApi(ctx, oauthOptions, "authorization_code"),
				body: ctx.body,
				clientVerified: false,
				budgetReservation: null,
			};
			const response =
				ctx.body.auth_session === undefined
					? await initialRequest(exchange)
					: await followUpRequest(exchange, ctx.body.auth_session);
			return ctx.json(response);
		},
	);
}

async function initialRequest(ex: Exchange): Promise<CodeResponse> {
	const { ctx, body, options, provider } = ex;
	const contentType = ctx.request?.headers.get("content-type") ?? "";
	if (!contentType.includes("application/x-www-form-urlencoded")) {
		invalidRequest(ERRORS.FORM_ENCODING_REQUIRED.message);
	}
	if (body.response_type === undefined) {
		invalidRequest(ERRORS.RESPONSE_TYPE_REQUIRED.message);
	}
	rejectUnsupportedParameters(body);
	if (
		options.methods.some((method) =>
			method.responseParameters.some((name) => body[name] !== undefined),
		)
	) {
		invalidRequest(ERRORS.CREDENTIAL_BEFORE_CHALLENGE.message);
	}
	const prompts = parsePrompt(body.prompt);
	if (prompts.has("none")) {
		challengeError(
			"BAD_REQUEST",
			"login_required",
			ERRORS.LOGIN_REQUIRED.message,
		);
	}
	if ([...prompts].some((prompt) => PAGE_PROMPTS.has(prompt))) {
		redirectToWeb();
	}

	await provider.challengeDpopNonce();
	const { client } = await provider.authenticateClient({
		requireCredentials: false,
		scopes: parseScopes(body.scope),
	});
	if (!(await options.isFirstPartyClient({ client, ctx }))) {
		challengeError(
			"BAD_REQUEST",
			"unauthorized_client",
			ERRORS.NOT_FIRST_PARTY.message,
		);
	}
	const proof = await provider.verifyDpopProof({
		required: options.requireDpop || client.dpopBoundAccessTokens === true,
	});
	ex.clientVerified = true;

	const loginHint = body.login_hint;
	const params = methodParams(body);
	const started = await startMethod(ex, client, { loginHint, params });
	if (!started) redirectToWeb();
	const { handle } = await createAuthSession(ctx, {
		clientId: client.clientId,
		userId: started.result.userId,
		sessionId: null,
		ownsSession: false,
		dpopJkt: proof?.jkt ?? null,
		state: "pending",
		method: started.method.id,
		methodState: await sealMethodState(ctx, {
			state: started.result.state,
			loginHint,
			startParams: params,
		}),
		request: JSON.stringify(pickAuthorizationRequest(body)),
		ceiling: null,
		amr: null,
		expiresAt: rowExpiry(options, { bound: true }),
	});
	return challenge(handle, started.method, started.result.challenge);
}

async function followUpRequest(
	ex: Exchange,
	handle: string,
): Promise<CodeResponse> {
	const { ctx, body, options, provider } = ex;
	const row = handle ? await findAuthSession(ctx, handle) : null;
	if (!row) invalidSession();
	if (new Date(row.expiresAt) <= new Date()) {
		await deleteAuthSession(ctx, row.id);
		invalidSession();
	}
	let live: LiveSession | null = null;
	if (row.state === "authenticated") {
		live = row.sessionId ? await findLiveSession(ctx, row.sessionId) : null;
		if (!live) {
			await deleteAuthSession(ctx, row.id);
			invalidSession();
		}
	}
	if (body.client_id !== undefined && body.client_id !== row.clientId) {
		challengeError(
			"BAD_REQUEST",
			"invalid_client",
			ERRORS.CLIENT_MISMATCH.message,
		);
	}
	const client = await provider.getClient(row.clientId);
	if (!client || client.disabled) {
		challengeError("BAD_REQUEST", "invalid_client", "client is disabled");
	}
	if (!(await options.isFirstPartyClient({ client, ctx }))) {
		if (row.state === "pending") await deleteAuthSession(ctx, row.id);
		challengeError(
			"BAD_REQUEST",
			"unauthorized_client",
			ERRORS.NOT_FIRST_PARTY.message,
		);
	}
	rejectUnsupportedParameters(body);
	await verifyFollowUp(ex, row, client);

	const method = row.method
		? options.methods.find((candidate) => candidate.id === row.method)
		: undefined;
	if (row.method && !method) {
		await deleteAuthSession(ctx, row.id);
		invalidSession();
	}
	if (
		method?.responseParameters.some((name) => body[name] !== undefined) === true
	) {
		if (AUTHORIZATION_PARAMETERS.some((name) => body[name] !== undefined)) {
			invalidRequest(ERRORS.UNEXPECTED_PARAMETERS.message);
		}
		return methodResponse(ex, row, handle, client, method, live);
	}
	if (row.state === "pending" && row.method) {
		invalidRequest(ERRORS.RESPONSE_REQUIRED.message);
	}
	const request = mergeRequest(row, body);
	await claim(ex, row);
	if (!live) return startForUser(ex, row, handle, client, request);
	return reEntry(ex, row, handle, client, live, request);
}

/** A response to the row's pending method challenge. */
async function methodResponse(
	ex: Exchange,
	row: FirstPartyAuthSession,
	handle: string,
	client: FirstPartyClient,
	method: FirstPartyMethod,
	live: LiveSession | null,
): Promise<CodeResponse> {
	const { ctx, options } = ex;
	const sealed = await openMethodState(ctx, row.methodState);
	if (!sealed) {
		await deleteAuthSession(ctx, row.id);
		invalidSession();
	}
	const budgetKey = await rowBudgetKey(ctx, method, row, sealed);
	await claim(ex, row);
	const locked =
		budgetKey !== null &&
		!(await reserveBudgetFailure(ctx, options, budgetKey));
	ex.budgetReservation = locked ? null : budgetKey;
	try {
		return await answerMethod(
			ex,
			row,
			handle,
			client,
			method,
			live,
			sealed,
			locked,
		);
	} finally {
		if (ex.budgetReservation) {
			await releaseBudgetFailure(ctx, options, ex.budgetReservation);
		}
	}
}

async function answerMethod(
	ex: Exchange,
	row: FirstPartyAuthSession,
	handle: string,
	client: FirstPartyClient,
	method: FirstPartyMethod,
	live: LiveSession | null,
	sealed: MethodState,
	locked: boolean,
): Promise<CodeResponse> {
	const { ctx, body } = ex;
	let result: FirstPartyMethodRespondResult = await method.respond({
		ctx,
		client,
		userId: row.userId ?? null,
		loginHint: sealed.loginHint,
		params: methodParams(body),
		state: sealed.state,
	});
	if (
		result.type === "authenticated" &&
		row.userId &&
		result.userId !== row.userId
	) {
		result = { type: "failed" };
	}
	// C1: a locked account's answers all count as failures on the row, so its
	// responses look the same whether the credential was right or wrong.
	if (locked && result.type !== "challenge") {
		return failedResponse(ex, row, handle, client, method, sealed);
	}
	switch (result.type) {
		case "challenge":
			await verify(ex, row);
			await updateAuthSession(ctx, row.id, {
				methodState: await sealMethodState(ctx, {
					...sealed,
					state: result.state,
				}),
			});
			return challenge(handle, method, result.challenge);
		case "failed":
			return failedResponse(ex, row, handle, client, method, sealed);
		case "redirect_to_web":
			await verify(ex, row);
			await leaveMethod(ctx, row);
			return redirectToWeb({ handle: live ? handle : undefined });
		case "authenticated":
			return authenticatedResponse(
				ex,
				row,
				handle,
				client,
				method,
				result,
				live,
			);
	}
}

async function failedResponse(
	ex: Exchange,
	row: FirstPartyAuthSession,
	handle: string,
	client: FirstPartyClient,
	method: FirstPartyMethod,
	sealed: MethodState,
): Promise<CodeResponse> {
	const { ctx, options } = ex;
	await verify(ex, row);
	// The verified failure keeps the budget slot its request reserved.
	ex.budgetReservation = null;
	const failures = row.failures + 1;
	if (failures >= options.authSession.maxFailures) {
		await endAuthSession(ctx, row);
		return redirectToWeb();
	}
	const user =
		sealed.loginHint === undefined && row.userId
			? ((await ctx.context.internalAdapter.findUserById(row.userId)) ??
				undefined)
			: undefined;
	const restarted = await method.start({
		ctx,
		client,
		...(user ? { user } : { loginHint: sealed.loginHint }),
		params: sealed.startParams,
		previous: { state: sealed.state },
	});
	if (!restarted || restarted.type === "redirect_to_web") {
		await leaveMethod(ctx, row);
		return redirectToWeb({
			handle: row.state === "authenticated" ? handle : undefined,
		});
	}
	await updateAuthSession(ctx, row.id, {
		failures,
		methodState: await sealMethodState(ctx, {
			...sealed,
			state: restarted.state,
		}),
	});
	return challengeError(
		"BAD_REQUEST",
		"authentication_failed",
		ERRORS.AUTHENTICATION_FAILED.message,
		{
			auth_session: handle,
			challenge_type: method.id,
			...challengeFields(restarted.challenge),
		},
	);
}

async function authenticatedResponse(
	ex: Exchange,
	row: FirstPartyAuthSession,
	handle: string,
	client: FirstPartyClient,
	method: FirstPartyMethod,
	result: { userId: string; amr?: readonly string[] },
	live: LiveSession | null,
): Promise<CodeResponse> {
	const { ctx, options } = ex;
	const user = (await ctx.context.internalAdapter.findUserById(
		result.userId,
	)) as (User & Record<string, unknown>) | null;
	if (!user) {
		const sealed = (await openMethodState(ctx, row.methodState))!;
		return failedResponse(ex, row, handle, client, method, sealed);
	}
	// The two-factor plugin verifies second factors only against its own
	// browser cookie, so an enrolled user finishes in the browser.
	if (user.twoFactorEnabled === true) {
		await verify(ex, row);
		await leaveMethod(ctx, row);
		return redirectToWeb({ handle: live ? handle : undefined });
	}
	const amr = [...(result.amr ?? method.amr)];
	const request = readRequest(row);
	const decision = await runPolicy(ex, client, user, request, {
		authTime: new Date(),
		amr,
		fresh: true,
	});
	if (
		decision?.type === "redirect_to_web" ||
		decision?.type === "reauthenticate"
	) {
		await verify(ex, row);
		await leaveMethod(ctx, row);
		return redirectToWeb({
			handle: live ? handle : undefined,
			description: decision.description,
		});
	}
	if (decision?.type === "insufficient_authorization") {
		await verify(ex, row);
		const session = await createFlowSession(ex, row, client, user, method, amr);
		await updateAuthSession(
			ctx,
			row.id,
			authenticatedUpdate(options, row, session, amr),
		);
		return insufficientAuthorization(handle, decision);
	}
	const session = await createFlowSession(ex, row, client, user, method, amr);
	return issueCode(ex, row, { session, user }, { createdSession: true, amr });
}

/**
 * A pending step-up row without a session: the user the grant named signs
 * in again.
 */
async function startForUser(
	ex: Exchange,
	row: FirstPartyAuthSession,
	handle: string,
	client: FirstPartyClient,
	request: FirstPartyAuthorizationRequest,
): Promise<CodeResponse> {
	await verify(ex, row);
	const user = row.userId
		? await ex.ctx.context.internalAdapter.findUserById(row.userId)
		: null;
	if (!user) {
		await deleteAuthSession(ex.ctx, row.id);
		invalidSession();
	}
	return beginReauthentication(ex, row, handle, client, user, request);
}

/** An authenticated row presented again (draft Appendix A.7). */
async function reEntry(
	ex: Exchange,
	row: FirstPartyAuthSession,
	handle: string,
	client: FirstPartyClient,
	live: LiveSession,
	request: FirstPartyAuthorizationRequest,
): Promise<CodeResponse> {
	const prompts = parsePrompt(request.prompt);
	if ([...prompts].some((prompt) => PAGE_PROMPTS.has(prompt))) {
		await verify(ex, row);
		await saveRequest(ex.ctx, row, request);
		redirectToWeb({ handle });
	}
	const createdAt = new Date(live.session.createdAt);
	const needsSignIn =
		prompts.has("login") ||
		(request.max_age !== undefined &&
			createdAt.getTime() + request.max_age * 1000 <= Date.now());
	if (needsSignIn) {
		await verify(ex, row);
		if (prompts.has("none")) {
			challengeError(
				"BAD_REQUEST",
				"login_required",
				ERRORS.LOGIN_REQUIRED.message,
			);
		}
		return beginReauthentication(ex, row, handle, client, live.user, request);
	}
	const decision = await runPolicy(ex, client, live.user, request, {
		authTime: createdAt,
		amr: row.amr ?? [],
		fresh: false,
	});
	if (decision) {
		await verify(ex, row);
		if (decision.type === "reauthenticate") {
			return beginReauthentication(ex, row, handle, client, live.user, request);
		}
		await saveRequest(ex.ctx, row, request);
		if (decision.type === "insufficient_authorization") {
			return insufficientAuthorization(handle, decision);
		}
		return redirectToWeb({ handle, description: decision.description });
	}
	return issueCode(ex, { ...row, request: JSON.stringify(request) }, live, {
		createdSession: false,
		amr: row.amr ?? [],
	});
}

/**
 * Starts a method for a known user. The request is verified first, because
 * `start` may reveal account details such as the user's credentials.
 */
async function beginReauthentication(
	ex: Exchange,
	row: FirstPartyAuthSession,
	handle: string,
	client: FirstPartyClient,
	user: User,
	request: FirstPartyAuthorizationRequest,
): Promise<CodeResponse> {
	const { ctx, body } = ex;
	const params = methodParams(body);
	const started = await startMethod(ex, client, { user, params });
	const authenticated = row.state === "authenticated";
	if (!started) {
		if (authenticated) {
			await updateAuthSession(ctx, row.id, {
				method: null,
				methodState: null,
				request: JSON.stringify(request),
			});
		} else {
			await deleteAuthSession(ctx, row.id);
		}
		return redirectToWeb({
			handle: authenticated ? handle : undefined,
			reauthenticate: request,
		});
	}
	await updateAuthSession(ctx, row.id, {
		method: started.method.id,
		methodState: await sealMethodState(ctx, {
			state: started.result.state,
			startParams: params,
		}),
		request: JSON.stringify(request),
	});
	return challenge(handle, started.method, started.result.challenge);
}

async function issueCode(
	ex: Exchange,
	row: FirstPartyAuthSession,
	live: LiveSession,
	issuance: { createdSession: boolean; amr: string[] },
): Promise<CodeResponse> {
	const { ctx, options } = ex;
	const request = readRequest(row);
	// The plugin verified this request's proof already, and the provider would
	// reject its `jti` as replayed. Without the header, `dpop_jkt` still binds
	// the code to the row's key, so only that key can redeem it.
	const headers = new Headers(ctx.headers);
	headers.delete("dpop");
	const provider = getOAuthProviderApi(
		{ ...ctx, headers },
		ex.oauthOptions,
		"authorization_code",
	);
	let code: string;
	try {
		({ code } = await provider.issueAuthorizationCode({
			query: {
				...request,
				code_challenge_method: request.code_challenge_method as
					| "S256"
					| undefined,
				prompt: request.prompt as never,
				client_id: row.clientId,
				response_type: "code",
				...(row.dpopJkt ? { dpop_jkt: row.dpopJkt } : {}),
			},
			session: live,
		}));
	} catch (error) {
		if (issuance.createdSession) {
			await ctx.context.internalAdapter.deleteSession(live.session.token);
		}
		const errorCode = isAPIError(error)
			? (error.body as { error?: string } | undefined)?.error
			: undefined;
		// A client that failed authentication here never proved itself, so the
		// row stays as a wrong credential would leave it. Otherwise a fresh
		// authentication spent the method's one-time state.
		if (errorCode !== "invalid_client") {
			if (row.state === "pending") await deleteAuthSession(ctx, row.id);
			else if (row.method) await leaveMethod(ctx, row);
		}
		if (!isAPIError(error)) throw error;
		if (
			errorCode === "consent_required" ||
			errorCode === "interaction_required"
		) {
			redirectToWeb({
				handle:
					row.state === "authenticated" ? ex.body.auth_session : undefined,
			});
		}
		throw error;
	}
	if (!row.dpopJkt) {
		// An unbound handle is a bearer credential, so it lasts one flow.
		await deleteAuthSession(ctx, row.id);
	} else {
		await updateAuthSession(ctx, row.id, {
			...authenticatedUpdate(options, row, live.session, issuance.amr),
			ownsSession: issuance.createdSession || row.ownsSession,
			request: JSON.stringify(withoutOneTimeParameters(request)),
		});
	}
	return { authorization_code: code };
}

function authenticatedUpdate(
	options: ResolvedFirstPartyAppsOptions,
	row: FirstPartyAuthSession,
	session: Session,
	amr: string[],
): Partial<FirstPartyAuthSession> {
	return {
		state: "authenticated",
		userId: session.userId,
		sessionId: session.id,
		ownsSession: true,
		amr,
		failures: 0,
		method: null,
		methodState: null,
		expiresAt: rowExpiry(options, {
			sessionExpiresAt: session.expiresAt,
			bound: !!row.dpopJkt,
		}),
	};
}

async function createFlowSession(
	ex: Exchange,
	row: FirstPartyAuthSession,
	client: FirstPartyClient,
	user: User,
	method: FirstPartyMethod,
	amr: string[],
): Promise<Session & Record<string, unknown>> {
	const { ctx, options } = ex;
	const fields = options.session.fields
		? await options.session.fields({
				ctx,
				client,
				user,
				method: method.id,
				amr,
			})
		: {};
	const override: Record<string, unknown> = Object.fromEntries(
		Object.entries(fields).filter(
			([name]) => !RESERVED_SESSION_FIELDS.has(name),
		),
	);
	if (options.session.expiresIn !== undefined) {
		override.expiresAt = new Date(
			Date.now() + options.session.expiresIn * 1000,
		);
	}
	try {
		return (await ctx.context.internalAdapter.createSession(
			user.id,
			false,
			override,
			true,
		)) as Session & Record<string, unknown>;
	} catch (error) {
		// A session hook refused the user, for example a banned account. The
		// credential verified, so answer only a verified request.
		if (!isAPIError(error)) throw error;
		await verify(ex, row);
		await leaveMethod(ctx, row);
		return challengeError(
			"BAD_REQUEST",
			"access_denied",
			ERRORS.ACCOUNT_CANNOT_SIGN_IN.message,
		);
	}
}

async function runPolicy(
	ex: Exchange,
	client: FirstPartyClient,
	user: User,
	request: FirstPartyAuthorizationRequest,
	authentication: { authTime: Date; amr: readonly string[]; fresh: boolean },
): Promise<Exclude<FirstPartyAuthorizationDecision, void | undefined> | null> {
	if (!ex.options.authorizationPolicy) return null;
	const decision = await ex.options.authorizationPolicy({
		ctx: ex.ctx,
		client,
		user,
		request: { ...request },
		authentication,
	});
	return decision ?? null;
}

/**
 * Verifies a later request before it changes anything: the DPoP proof for
 * the row's key (draft §9.6.1), or no proof for a row without a binding, and
 * the client, unless it authenticates with a single-use assertion.
 */
async function verifyFollowUp(
	ex: Exchange,
	row: FirstPartyAuthSession,
	client: FirstPartyClient,
): Promise<void> {
	if (row.dpopJkt) {
		await ex.provider.verifyDpopProof({ expectedJkt: row.dpopJkt });
	} else if (ex.ctx.headers?.get("dpop")) {
		challengeError(
			"BAD_REQUEST",
			"invalid_dpop_proof",
			ERRORS.DPOP_NOT_EXPECTED.message,
		);
	}
	if (
		REPEATABLE_AUTH_METHODS.has(
			client.tokenEndpointAuthMethod ?? "client_secret_basic",
		)
	) {
		await verify(ex, row);
	}
}

/**
 * Authenticates the client on an answer other than a code, when the request
 * has not done so yet. On a request that ends in a code, an assertion client
 * authenticates through `issueAuthorizationCode`.
 */
async function verify(ex: Exchange, row: FirstPartyAuthSession): Promise<void> {
	if (ex.clientVerified) return;
	await ex.provider.authenticateClient({
		clientId: row.clientId,
		requireCredentials: false,
	});
	ex.clientVerified = true;
}

async function claim(ex: Exchange, row: FirstPartyAuthSession): Promise<void> {
	if (await claimAuthSession(ex.ctx, ex.options, row)) return;
	if (
		row.state === "pending" &&
		row.attempts >= ex.options.authSession.maxRequests
	) {
		await deleteAuthSession(ex.ctx, row.id);
	}
	invalidSession();
}

async function startMethod(
	ex: Exchange,
	client: FirstPartyClient,
	input: { loginHint?: string; user?: User; params: Record<string, unknown> },
): Promise<{
	method: FirstPartyMethod;
	result: Extract<FirstPartyMethodStartResult, { type: "challenge" }>;
} | null> {
	for (const method of ex.options.methods) {
		const result = await method.start({ ctx: ex.ctx, client, ...input });
		if (!result) continue;
		if (result.type === "redirect_to_web") return null;
		return { method, result };
	}
	return null;
}

/** The C1 key: the account when the method named one, the hint otherwise. */
async function rowBudgetKey(
	ctx: GenericEndpointContext,
	method: FirstPartyMethod,
	row: FirstPartyAuthSession,
	sealed: MethodState,
): Promise<string | null> {
	if (row.userId) return getBudgetKey(ctx, method.id, { userId: row.userId });
	if (sealed.loginHint) {
		return getBudgetKey(ctx, method.id, { loginHint: sealed.loginHint });
	}
	return null;
}

/** Clears a pending challenge. A pending row ends with it. */
async function leaveMethod(
	ctx: GenericEndpointContext,
	row: FirstPartyAuthSession,
): Promise<void> {
	if (row.state === "pending") {
		await deleteAuthSession(ctx, row.id);
		return;
	}
	await updateAuthSession(ctx, row.id, { method: null, methodState: null });
}

async function saveRequest(
	ctx: GenericEndpointContext,
	row: FirstPartyAuthSession,
	request: FirstPartyAuthorizationRequest,
): Promise<void> {
	await updateAuthSession(ctx, row.id, { request: JSON.stringify(request) });
}

/**
 * Applies a later request's authorization parameters to the stored request.
 * A step-up row cannot widen the grant it came from.
 */
function mergeRequest(
	row: FirstPartyAuthSession,
	body: Body,
): FirstPartyAuthorizationRequest {
	const next: Record<string, unknown> = { ...readRequest(row) };
	for (const name of AUTHORIZATION_PARAMETERS) {
		if (body[name] !== undefined) next[name] = body[name];
	}
	const request = next as FirstPartyAuthorizationRequest;
	const ceiling = readCeiling(row);
	if (!ceiling) return request;
	const allowedScopes = new Set(parseScopes(ceiling.scope));
	if (parseScopes(request.scope).some((scope) => !allowedScopes.has(scope))) {
		challengeError(
			"BAD_REQUEST",
			"invalid_scope",
			ERRORS.SCOPE_EXCEEDS_GRANT.message,
		);
	}
	const allowedResources = new Set(ceiling.resource ?? []);
	if (
		(toResourceList(request.resource) ?? []).some(
			(resource) => !allowedResources.has(resource),
		)
	) {
		challengeError(
			"BAD_REQUEST",
			"invalid_target",
			ERRORS.RESOURCE_EXCEEDS_GRANT.message,
		);
	}
	if (request.claims !== ceiling.claims) {
		invalidRequest(ERRORS.CLAIMS_EXCEED_GRANT.message);
	}
	return request;
}

function rejectUnsupportedParameters(body: Body): void {
	// Draft Appendix A.7: a later request may omit response_type.
	if (body.response_type !== undefined && body.response_type !== "code") {
		challengeError(
			"BAD_REQUEST",
			"unsupported_response_type",
			ERRORS.UNSUPPORTED_RESPONSE_TYPE.message,
		);
	}
	if (body.request_uri !== undefined) {
		invalidRequest(ERRORS.REQUEST_URI_NOT_ACCEPTED.message);
	}
	if (body.request !== undefined) {
		challengeError(
			"BAD_REQUEST",
			"request_not_supported",
			ERRORS.REQUEST_OBJECT_NOT_SUPPORTED.message,
		);
	}
	// Draft §6: the token request carries no redirect_uri, so the code is
	// never bound to one.
	if (body.redirect_uri !== undefined) {
		invalidRequest(ERRORS.REDIRECT_URI_NOT_ACCEPTED.message);
	}
}

function pickAuthorizationRequest(body: Body): FirstPartyAuthorizationRequest {
	const request: Record<string, unknown> = {};
	for (const name of AUTHORIZATION_PARAMETERS) {
		if (body[name] !== undefined) request[name] = body[name];
	}
	return request as FirstPartyAuthorizationRequest;
}

function withoutOneTimeParameters(
	request: FirstPartyAuthorizationRequest,
): FirstPartyAuthorizationRequest {
	const next: Record<string, unknown> = { ...request };
	for (const name of ONE_TIME_PARAMETERS) delete next[name];
	return next as FirstPartyAuthorizationRequest;
}

function methodParams(body: Body): Record<string, unknown> {
	return Object.fromEntries(
		Object.entries(body).filter(([name]) => !OWNED_PARAMETERS.has(name)),
	);
}

function parsePrompt(prompt: string | undefined): Set<string> {
	return new Set(parseScopes(prompt));
}

function challengeFields(
	fields: Record<string, unknown> | undefined,
): Record<string, unknown> {
	return Object.fromEntries(
		Object.entries(fields ?? {}).filter(
			([name]) => !OWNED_RESPONSE_FIELDS.has(name),
		),
	);
}

function challenge(
	handle: string,
	method: FirstPartyMethod,
	fields: Record<string, unknown> | undefined,
): never {
	return challengeError("FORBIDDEN", "insufficient_authorization", undefined, {
		auth_session: handle,
		challenge_type: method.id,
		...challengeFields(fields),
	});
}

function insufficientAuthorization(
	handle: string,
	decision: { description?: string; fields?: Record<string, unknown> },
): never {
	return challengeError(
		"FORBIDDEN",
		"insufficient_authorization",
		decision.description,
		{ ...challengeFields(decision.fields), auth_session: handle },
	);
}

/**
 * 403 `redirect_to_web` (draft §5.2.2.1). A re-authentication carries the
 * hints the browser request needs (C3). `auth_session` appears only when the
 * row stays authenticated.
 */
function redirectToWeb(input?: {
	handle?: string;
	description?: string;
	reauthenticate?: FirstPartyAuthorizationRequest;
}): never {
	return challengeError(
		"FORBIDDEN",
		"redirect_to_web",
		input?.description ?? ERRORS.BROWSER_REQUIRED.message,
		{
			...(input?.handle ? { auth_session: input.handle } : {}),
			...(input?.reauthenticate
				? {
						...(input.reauthenticate.acr_values
							? { acr_values: input.reauthenticate.acr_values }
							: {}),
						max_age: 0,
					}
				: {}),
		},
	);
}
