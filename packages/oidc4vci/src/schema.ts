import type { BetterAuthPluginDBSchema } from "@better-auth/core/db";

export const schema = {
	oidc4vciOffer: {
		modelName: "oidc4vciOffer",
		fields: {
			walletClientId: {
				type: "string",
				required: true,
			},
			userId: {
				type: "string",
				required: true,
				references: {
					model: "user",
					field: "id",
					onDelete: "cascade",
				},
				index: true,
			},
			credentialConfigurationId: {
				type: "string",
				required: true,
			},
			preAuthorizedCodeEncrypted: {
				type: "string",
				required: true,
			},
			txCodeHash: {
				type: "string",
				required: false,
			},
			txCodeInputMode: {
				type: "string",
				required: false,
			},
			txCodeLength: {
				type: "number",
				required: false,
			},
			issuerState: {
				type: "string",
				required: false,
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
		},
	},
	oidc4vciIssuedCredential: {
		modelName: "oidc4vciIssuedCredential",
		fields: {
			userId: {
				type: "string",
				required: true,
				references: {
					model: "user",
					field: "id",
					onDelete: "cascade",
				},
				index: true,
			},
			credentialConfigurationId: {
				type: "string",
				required: true,
			},
			format: {
				type: "string",
				required: true,
			},
			statusListId: {
				type: "string",
				required: true,
			},
			statusListIndex: {
				type: "number",
				required: true,
			},
			status: {
				type: "number",
				required: true,
				defaultValue: 0,
			},
			revokedAt: {
				type: "date",
				required: false,
			},
			credential: {
				type: "string",
				required: true,
			},
			createdAt: {
				type: "date",
				required: true,
			},
		},
	},
} satisfies BetterAuthPluginDBSchema;
