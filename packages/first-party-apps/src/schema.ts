import type { BetterAuthPluginDBSchema } from "@better-auth/core/db";

/**
 * `firstPartyAuthSession` holds one `auth_session` (draft §5.3.1).
 * Lifecycle: `pending` until a credential proves the user, then
 * `authenticated` while its backing session lives.
 *
 * `firstPartyFailureBudget` holds the per-account failure counters.
 */
export const schema = {
	firstPartyAuthSession: {
		fields: {
			/**
			 * HMAC-SHA-256 of the handle, keyed by the auth secret. The raw handle
			 * is returned to the client and never stored.
			 */
			authSession: {
				type: "string",
				required: true,
				unique: true,
			},
			clientId: {
				type: "string",
				required: true,
				references: {
					model: "oauthClient",
					field: "clientId",
					onDelete: "cascade",
				},
				index: true,
			},
			/**
			 * Pending: the account the method's challenge is for, which no
			 * credential has proven yet. Authenticated: the proven user.
			 */
			userId: {
				type: "string",
				required: false,
				references: { model: "user", field: "id", onDelete: "cascade" },
				index: true,
			},
			/** The backing session. Set exactly when the row is authenticated. */
			sessionId: {
				type: "string",
				required: false,
				references: { model: "session", field: "id", onDelete: "cascade" },
				index: true,
			},
			/** Whether the plugin created `sessionId` for this flow. */
			ownsSession: {
				type: "boolean",
				required: true,
				defaultValue: false,
			},
			/** RFC 7638 thumbprint of the key the row is bound to. Never changes. */
			dpopJkt: {
				type: "string",
				required: false,
			},
			/** `pending` or `authenticated`. */
			state: {
				type: "string",
				required: true,
			},
			/** The method whose challenge is waiting for a response. */
			method: {
				type: "string",
				required: false,
			},
			/**
			 * The method's state, the flow's `login_hint`, and the parameters that
			 * started the method, as JSON encrypted with the auth secret.
			 */
			methodState: {
				type: "string",
				required: false,
			},
			/** The authorization request as JSON, without client credentials. */
			request: {
				type: "string",
				required: true,
			},
			/**
			 * For a step-up row, the authorization the grant held, as JSON. Later
			 * requests can narrow it but not widen it.
			 */
			ceiling: {
				type: "string",
				required: false,
			},
			/** What the backing session proved. */
			amr: {
				type: "string[]",
				required: false,
			},
			/** Failed responses since the row's user last authenticated. */
			failures: {
				type: "number",
				required: true,
				defaultValue: 0,
			},
			/** Requests that advanced the row. Also the row's version for claims. */
			attempts: {
				type: "number",
				required: true,
				defaultValue: 0,
			},
			expiresAt: {
				type: "date",
				required: true,
				index: true,
			},
			createdAt: {
				type: "date",
				required: true,
			},
			updatedAt: {
				type: "date",
				required: true,
			},
		},
	},
	firstPartyFailureBudget: {
		fields: {
			/** HMAC-SHA-256 of the method id and the account or hint. */
			key: {
				type: "string",
				required: true,
				unique: true,
			},
			failures: {
				type: "number",
				required: true,
			},
			resetAt: {
				type: "date",
				required: true,
			},
		},
	},
} satisfies BetterAuthPluginDBSchema;
