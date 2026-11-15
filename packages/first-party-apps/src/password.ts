import type { GenericEndpointContext } from "@better-auth/core";
import type { Account, User } from "@better-auth/core/db";
import { BetterAuthError } from "@better-auth/core/error";
import * as z from "zod";
import type { FirstPartyMethod } from "./types";

const DEFAULT_MAX_PASSWORD_LENGTH = 128;

/**
 * Email and password sign-in for Better Auth credential accounts, checked as
 * `/sign-in/email` checks them. The challenge carries no fields and looks the
 * same for known and unknown addresses.
 */
export function passwordMethod(): FirstPartyMethod {
	return {
		id: "password",
		amr: ["pwd"],
		responseParameters: ["password"],
		init(ctx) {
			if (!ctx.options.emailAndPassword?.enabled) {
				throw new BetterAuthError(
					"passwordMethod() requires `emailAndPassword: { enabled: true }`.",
				);
			}
		},
		async start({ ctx, loginHint, user }) {
			if (user) {
				const account = await findCredentialAccount(ctx, user.id);
				return account?.password
					? { type: "challenge", userId: user.id }
					: null;
			}
			if (!loginHint || !z.email().safeParse(loginHint).success) return null;
			const found = await ctx.context.internalAdapter.findUserByEmail(
				loginHint.toLowerCase(),
			);
			return { type: "challenge", userId: found?.user.id ?? null };
		},
		async respond({ ctx, userId, params }) {
			const { password } = params;
			if (typeof password !== "string" || !password) return { type: "failed" };
			const maxLength =
				ctx.context.options.emailAndPassword?.maxPasswordLength ??
				DEFAULT_MAX_PASSWORD_LENGTH;
			if (password.length > maxLength) return { type: "failed" };

			const user = userId
				? await ctx.context.internalAdapter.findUserById(userId)
				: null;
			const account = user ? await findCredentialAccount(ctx, user.id) : null;
			if (!user || !account?.password) {
				// Hash anyway, so an unknown account takes as long as a known one.
				await ctx.context.password.hash(password);
				return { type: "failed" };
			}
			const valid = await ctx.context.password.verify({
				hash: account.password,
				password,
			});
			if (!valid) return { type: "failed" };
			if (
				ctx.context.options.emailAndPassword?.requireEmailVerification &&
				!user.emailVerified
			) {
				return { type: "redirect_to_web" };
			}
			return { type: "authenticated", userId: user.id };
		},
	};
}

async function findCredentialAccount(
	ctx: GenericEndpointContext,
	userId: User["id"],
): Promise<Account | undefined> {
	const accounts = await ctx.context.internalAdapter.findAccounts(userId);
	return accounts.find(
		(account) =>
			account.providerId === "credential" && account.accountId === userId,
	);
}
