import { sql } from "drizzle-orm";
import { index, integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

import { users } from "./auth";

export const oidc4vciOffers = sqliteTable(
	"oidc4vci_offer",
	{
		id: text("id").primaryKey().default(sql`(lower(hex(randomblob(16))))`),
		walletClientId: text("wallet_client_id").notNull(),
		userId: text("user_id")
			.notNull()
			.references(() => users.id, { onDelete: "cascade" }),
		credentialConfigurationId: text("credential_configuration_id").notNull(),
		preAuthorizedCodeEncrypted: text("pre_authorized_code_encrypted").notNull(),
		txCodeHash: text("tx_code_hash"),
		issuerState: text("issuer_state"),
		expiresAt: text("expires_at").notNull(),
		createdAt: text("created_at").notNull().default(sql`(datetime('now'))`),
	},
	(table) => ({
		userIdIdx: index("oidc4vci_offer_user_id_idx").on(table.userId),
		expiresAtIdx: index("oidc4vci_offer_expires_at_idx").on(table.expiresAt),
	}),
);

export const oidc4vciIssuedCredentials = sqliteTable(
	"oidc4vci_issued_credential",
	{
		id: text("id").primaryKey().default(sql`(lower(hex(randomblob(16))))`),
		userId: text("user_id")
			.notNull()
			.references(() => users.id, { onDelete: "cascade" }),
		credentialConfigurationId: text("credential_configuration_id").notNull(),
		format: text("format").notNull(),
		statusListId: text("status_list_id").notNull(),
		statusListIndex: integer("status_list_index").notNull(),
		status: integer("status").notNull().default(0),
		revokedAt: text("revoked_at"),
		credential: text("credential").notNull(),
		createdAt: text("created_at").notNull().default(sql`(datetime('now'))`),
	},
	(table) => ({
		userIdIdx: index("oidc4vci_issued_credential_user_id_idx").on(table.userId),
	}),
);

export type Oidc4vciOffer = typeof oidc4vciOffers.$inferSelect;
export type NewOidc4vciOffer = typeof oidc4vciOffers.$inferInsert;
export type Oidc4vciIssuedCredential =
	typeof oidc4vciIssuedCredentials.$inferSelect;
export type NewOidc4vciIssuedCredential =
	typeof oidc4vciIssuedCredentials.$inferInsert;
