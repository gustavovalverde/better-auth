import type { GenericEndpointContext } from "@better-auth/core";
import { createHMAC } from "@better-auth/utils/hmac";
import type {
	FirstPartyFailureBudget,
	ResolvedFirstPartyAppsOptions,
} from "./types";

const BUDGET_MODEL = "firstPartyFailureBudget";

/**
 * The budget key for a method and an account, or for the hint when the
 * account is unknown. A keyed hash, so the table holds no identifier in the
 * clear.
 */
export async function getBudgetKey(
	ctx: GenericEndpointContext,
	methodId: string,
	subject: { userId: string } | { loginHint: string },
): Promise<string> {
	const value =
		"userId" in subject
			? `user:${subject.userId}`
			: `hint:${subject.loginHint.trim().toLowerCase()}`;
	return createHMAC("SHA-256", "base64urlnopad").sign(
		ctx.context.secret,
		`first-party-apps:failure-budget:${methodId}:${value}`,
	);
}

export async function isBudgetLocked(
	ctx: GenericEndpointContext,
	options: ResolvedFirstPartyAppsOptions,
	key: string | null,
): Promise<boolean> {
	if (!options.failureBudget || !key) return false;
	const budget = await ctx.context.adapter.findOne<FirstPartyFailureBudget>({
		model: BUDGET_MODEL,
		where: [{ field: "key", value: key }],
	});
	return (
		!!budget &&
		new Date(budget.resetAt) > new Date() &&
		budget.failures >= options.failureBudget.maxFailures
	);
}

/** Counts one failure. A success never resets the window. */
export async function recordBudgetFailure(
	ctx: GenericEndpointContext,
	options: ResolvedFirstPartyAppsOptions,
	key: string | null,
): Promise<void> {
	if (!options.failureBudget || !key) return;
	const now = new Date();
	const resetAt = new Date(now.getTime() + options.failureBudget.window * 1000);
	const { adapter } = ctx.context;
	const budget = await adapter.findOne<FirstPartyFailureBudget>({
		model: BUDGET_MODEL,
		where: [{ field: "key", value: key }],
	});
	if (!budget) {
		try {
			await adapter.create({
				model: BUDGET_MODEL,
				data: { key, failures: 1, resetAt },
			});
			return;
		} catch {
			// A concurrent failure created the row first; count on it below.
		}
	} else if (new Date(budget.resetAt) <= now) {
		await adapter.update({
			model: BUDGET_MODEL,
			where: [{ field: "key", value: key }],
			update: { failures: 1, resetAt },
		});
		return;
	}
	await adapter.incrementOne({
		model: BUDGET_MODEL,
		where: [{ field: "key", value: key }],
		increment: { failures: 1 },
	});
}
