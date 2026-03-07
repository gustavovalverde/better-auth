import { sql } from "drizzle-orm";
import { index, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

import { users } from "./auth";

export const oidc4idaVerifiedClaims = sqliteTable(
	"oidc4ida_verified_claim",
	{
		id: text("id").primaryKey().default(sql`(lower(hex(randomblob(16))))`),
		userId: text("user_id")
			.notNull()
			.references(() => users.id, { onDelete: "cascade" }),
		verifiedClaims: text("verified_claims").notNull(),
		createdAt: text("created_at").notNull().default(sql`(datetime('now'))`),
		updatedAt: text("updated_at").notNull().default(sql`(datetime('now'))`),
	},
	(table) => ({
		userIdIdx: index("oidc4ida_verified_claim_user_id_idx").on(table.userId),
		userIdUnique: uniqueIndex("oidc4ida_verified_claim_user_id_unique").on(
			table.userId,
		),
	}),
);

export type Oidc4idaVerifiedClaim = typeof oidc4idaVerifiedClaims.$inferSelect;
export type NewOidc4idaVerifiedClaim =
	typeof oidc4idaVerifiedClaims.$inferInsert;
