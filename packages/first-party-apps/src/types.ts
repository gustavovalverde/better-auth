import type {
	AuthContext,
	Awaitable,
	GenericEndpointContext,
} from "@better-auth/core";
import type { Session, User } from "@better-auth/core/db";
import type { SchemaClient, Scope } from "@better-auth/oauth-provider";
import type { schema } from "./schema";

export type FirstPartyClient = SchemaClient<Scope[]>;

/**
 * The authorization request a code is issued for, as the client sent it on the
 * initial request or replaced it on a later one.
 */
export interface FirstPartyAuthorizationRequest {
	scope?: string;
	resource?: string | string[];
	claims?: string;
	acr_values?: string;
	max_age?: number;
	prompt?: string;
	nonce?: string;
	code_challenge?: string;
	code_challenge_method?: string;
	ui_locales?: string;
}

export interface FirstPartyMethodStartInput {
	ctx: GenericEndpointContext;
	client: FirstPartyClient;
	/** The `login_hint` of an initial request. Absent when `user` is set. */
	loginHint?: string;
	/** The user to authenticate again, for step-up or an elapsed `max_age`. */
	user?: User;
	/**
	 * Request parameters the plugin does not own, such as a method-specific
	 * `chain_id`. On a restart after a failed response, these are the
	 * parameters of the request that started the flow.
	 */
	params: Record<string, unknown>;
	/**
	 * Set when the plugin starts the method again after a failed response in
	 * the same flow. `state` is the state of the challenge that failed.
	 */
	previous?: { state: unknown };
}

export type FirstPartyMethodStartResult =
	| {
			type: "challenge";
			/**
			 * The account the challenge is for, or null for an unknown or not yet
			 * identified account. It also selects the failure-budget key: the
			 * account when it is known, the hint otherwise.
			 */
			userId: string | null;
			/** Fields added to the 403 response next to `challenge_type`. */
			challenge?: Record<string, unknown>;
			/** JSON-serializable state for `respond`. The plugin encrypts it at rest. */
			state?: unknown;
	  }
	| { type: "redirect_to_web" };

export interface FirstPartyMethodRespondInput {
	ctx: GenericEndpointContext;
	client: FirstPartyClient;
	/** The `userId` that `start` returned. */
	userId: string | null;
	/** The `login_hint` the flow started with, when it started from one. */
	loginHint?: string;
	params: Record<string, unknown>;
	state: unknown;
}

export type FirstPartyMethodRespondResult =
	| { type: "challenge"; challenge?: Record<string, unknown>; state?: unknown }
	| { type: "authenticated"; userId: string; amr?: readonly string[] }
	/** The credential verified, but the account must finish in the browser, for example to verify its email. */
	| { type: "redirect_to_web" }
	| { type: "failed" };

/**
 * A credential check. `start` issues a challenge and `respond` checks the
 * client's answer, possibly over several rounds.
 */
export interface FirstPartyMethod {
	/** The `challenge_type` clients see, and part of the failure-budget key. */
	id: string;
	/** RFC 8176 values this method proves, such as `["pwd"]`. */
	amr: readonly string[];
	/**
	 * Request parameters that carry a response to this method's challenge.
	 * They must not overlap the parameters the plugin owns or another
	 * method's.
	 */
	responseParameters: readonly string[];
	/** Called from the plugin's `init`, to fail fast on missing configuration. */
	init?: (ctx: AuthContext) => void;
	start: (
		input: FirstPartyMethodStartInput,
	) => Awaitable<FirstPartyMethodStartResult | null>;
	/**
	 * Runs after the plugin verified the request's DPoP proof and client. For
	 * a client that authenticates with a single-use assertion, the provider
	 * checks the assertion only when it issues the code, so keep `respond`
	 * free of effects the user would notice.
	 */
	respond: (
		input: FirstPartyMethodRespondInput,
	) => Awaitable<FirstPartyMethodRespondResult>;
}

export type FirstPartyAuthorizationDecision =
	| undefined
	| void
	| {
			type: "insufficient_authorization";
			description?: string;
			fields?: Record<string, unknown>;
	  }
	| { type: "reauthenticate"; description?: string }
	| { type: "redirect_to_web"; description?: string };

export interface FirstPartyAuthorizationPolicyInput {
	ctx: GenericEndpointContext;
	client: FirstPartyClient;
	user: User;
	request: FirstPartyAuthorizationRequest;
	authentication: {
		authTime: Date;
		amr: readonly string[];
		/** True when the user proved a credential in this request. */
		fresh: boolean;
	};
}

export interface FirstPartySessionFieldsInput {
	ctx: GenericEndpointContext;
	client: FirstPartyClient;
	user: User;
	method: string;
	amr: readonly string[];
}

export interface FirstPartyAppsOptions {
	/**
	 * Decides whether a client may use the endpoint (draft §5, §9.1). Called on
	 * every request. Return `false` for browser-based clients unless there is a
	 * reason to allow them (§9.8).
	 */
	isFirstPartyClient: (input: {
		client: FirstPartyClient;
		ctx: GenericEndpointContext;
	}) => Awaitable<boolean>;
	/** Credential methods, in order of preference. At least one. */
	methods: FirstPartyMethod[];
	/**
	 * Runs before every code the plugin issues, after the request's DPoP proof
	 * is verified. It must not change state.
	 */
	authorizationPolicy?: (
		input: FirstPartyAuthorizationPolicyInput,
	) => Awaitable<FirstPartyAuthorizationDecision>;
	/**
	 * Require a DPoP proof on the initial request, which binds the
	 * `auth_session` and the code to the client's key (draft §5.3.1, §9.6).
	 * A client registered with `dpop_bound_access_tokens` always needs one.
	 *
	 * @default false
	 */
	requireDpop?: boolean;
	session?: {
		/**
		 * Lifetime in seconds of a session the plugin creates. It bounds the
		 * tokens issued from it.
		 *
		 * @default the app's `session.expiresIn`
		 */
		expiresIn?: number;
		/**
		 * Extra fields for a session the plugin creates, before the code is
		 * issued. When issuance then fails, the plugin deletes the session
		 * through the internal adapter, so clean up anything this callback
		 * created in a session delete hook.
		 */
		fields?: (
			input: FirstPartySessionFieldsInput,
		) => Awaitable<Record<string, unknown>>;
	};
	authSession?: {
		/**
		 * Lifetime in seconds of an `auth_session` whose user has not
		 * authenticated yet, and the most an `auth_session` without a DPoP
		 * binding lives.
		 *
		 * @default 600
		 */
		expiresIn?: number;
		/**
		 * Failed responses one `auth_session` allows before the plugin answers
		 * `redirect_to_web` and ends it.
		 *
		 * @default 3
		 */
		maxFailures?: number;
		/**
		 * Requests one pending `auth_session` allows (draft §9.3).
		 *
		 * @default 20
		 */
		maxRequests?: number;
	};
	/**
	 * Failed responses allowed per account and method within `window`
	 * seconds. A locked account answers every response as a failure.
	 *
	 * @default { maxFailures: 10, window: 900 }
	 */
	failureBudget?: { maxFailures?: number; window?: number } | false;
	/**
	 * Per-IP limit on the endpoint.
	 *
	 * @default { window: 60, max: 10 }
	 */
	rateLimit?: { window?: number; max?: number };
	/** Model and field name overrides. */
	schema?: FirstPartyAppsSchemaOptions;
}

export type FirstPartyAppsSchemaOptions = {
	[Model in keyof typeof schema]?: {
		modelName?: string;
		fields?: {
			[Field in keyof (typeof schema)[Model]["fields"]]?: string;
		};
	};
};

export interface ResolvedFirstPartyAppsOptions {
	isFirstPartyClient: FirstPartyAppsOptions["isFirstPartyClient"];
	methods: FirstPartyMethod[];
	authorizationPolicy?: FirstPartyAppsOptions["authorizationPolicy"];
	requireDpop: boolean;
	session: {
		expiresIn?: number;
		fields?: NonNullable<FirstPartyAppsOptions["session"]>["fields"];
	};
	authSession: { expiresIn: number; maxFailures: number; maxRequests: number };
	failureBudget: { maxFailures: number; window: number } | false;
	rateLimit: { window: number; max: number };
}

/**
 * Input of {@link challengeFirstPartyStepUp}. The caller must already have
 * verified the grant credential (the refresh token or CIBA request), that it
 * belongs to `clientId`, and that it has not expired. The helper trusts these
 * facts and verifies only the request itself.
 */
export interface FirstPartyStepUpInput {
	/** The client the grant was issued to. The token request must authenticate as this client. */
	clientId: string;
	userId: string;
	/** The grant's session, or null when it has none. A follow-up reuses a live one. */
	sessionId: string | null;
	/** The key the grant is bound to (`cnf.jkt`), or null for a grant without DPoP binding. */
	dpopJkt: string | null;
	/**
	 * The authorization the grant holds. A follow-up can narrow it but never
	 * widen it. Authorization codes cannot carry RFC 9396
	 * `authorization_details`, so do not offer a step-up for a grant whose
	 * tokens depend on them.
	 */
	request: {
		scope: string;
		resource?: string | string[];
		claims?: string;
		acr_values?: string;
		max_age?: number;
	};
	description?: string;
	fields?: Record<string, unknown>;
}

export interface FirstPartyAuthSession {
	id: string;
	authSession: string;
	clientId: string;
	userId?: string | null;
	sessionId?: string | null;
	ownsSession: boolean;
	dpopJkt?: string | null;
	state: "pending" | "authenticated";
	method?: string | null;
	methodState?: string | null;
	request: string;
	ceiling?: string | null;
	amr?: string[] | null;
	failures: number;
	attempts: number;
	expiresAt: Date;
	createdAt: Date;
	updatedAt: Date;
}

export interface FirstPartyFailureBudget {
	id: string;
	key: string;
	failures: number;
	resetAt: Date;
}

export type { Session, User };
