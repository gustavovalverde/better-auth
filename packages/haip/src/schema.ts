import type { BetterAuthPluginDBSchema } from "@better-auth/core/db";

export const schema = {
	haipPushedRequest: {
		modelName: "haipPushedRequest",
		fields: {
			requestId: {
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
				},
			},
			requestParams: {
				type: "string",
				required: true,
			},
			expiresAt: {
				type: "date",
				required: true,
			},
		},
	},
	haipVpSession: {
		modelName: "haipVpSession",
		fields: {
			sessionId: {
				type: "string",
				required: true,
				unique: true,
			},
			nonce: {
				type: "string",
				required: true,
				unique: true,
			},
			state: {
				type: "string",
				required: true,
			},
			dcqlQuery: {
				type: "string",
				required: true,
			},
			responseUri: {
				type: "string",
				required: true,
			},
			clientId: {
				type: "string",
			},
			clientIdScheme: {
				type: "string",
			},
			responseMode: {
				type: "string",
				required: true,
			},
			expiresAt: {
				type: "date",
				required: true,
			},
		},
	},
} satisfies BetterAuthPluginDBSchema;
