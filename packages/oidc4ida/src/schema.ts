import type { BetterAuthPluginDBSchema } from "@better-auth/core/db";

export const schema = {
	oidc4idaVerifiedClaim: {
		modelName: "oidc4idaVerifiedClaim",
		fields: {
			userId: {
				type: "string",
				required: true,
				unique: true,
				references: {
					model: "user",
					field: "id",
					onDelete: "cascade",
				},
				index: true,
			},
			verifiedClaims: {
				type: "string",
				required: true,
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
} satisfies BetterAuthPluginDBSchema;
