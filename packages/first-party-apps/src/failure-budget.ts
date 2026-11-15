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

/**
 * Counts one failure before the method checks the credential, so requests
 * that run concurrently cannot check more credentials than the budget allows.
 * Returns false, and counts nothing, when the account is locked. A response
 * that turns out not to fail gives its failure back with `releaseBudgetFailure`.
 */
export async function reserveBudgetFailure(
	ctx: GenericEndpointContext,
	options: ResolvedFirstPartyAppsOptions,
	key: string,
): Promise<boolean> {
	if (!options.failureBudget) return true;
	const { maxFailures, window } = options.failureBudget;
	const { adapter } = ctx.context;
	for (let attempt = 0; attempt < 3; attempt++) {
		const now = new Date();
		const reserved = await adapter.incrementOne({
			model: BUDGET_MODEL,
			where: [
				{ field: "key", value: key },
				{ field: "resetAt", operator: "gt", value: now },
				{ field: "failures", operator: "lt", value: maxFailures },
			],
			increment: { failures: 1 },
		});
		if (reserved) return true;
		const budget = await adapter.findOne<FirstPartyFailureBudget>({
			model: BUDGET_MODEL,
			where: [{ field: "key", value: key }],
		});
		const resetAt = new Date(now.getTime() + window * 1000);
		if (!budget) {
			try {
				await adapter.create({
					model: BUDGET_MODEL,
					data: { key, failures: 1, resetAt },
				});
				return true;
			} catch {
				// A concurrent request created the row first.
				continue;
			}
		}
		if (new Date(budget.resetAt) > now) {
			if (budget.failures >= maxFailures) return false;
			continue;
		}
		// The window passed. Only one of the requests that saw it pass restarts it.
		const restarted = await adapter.incrementOne({
			model: BUDGET_MODEL,
			where: [
				{ field: "key", value: key },
				{ field: "resetAt", operator: "lte", value: now },
				{ field: "failures", value: budget.failures },
			],
			increment: { failures: 1 - budget.failures },
			set: { resetAt },
		});
		if (restarted) return true;
	}
	return false;
}

/** Gives back a failure `reserveBudgetFailure` counted for a response that did not fail. */
export async function releaseBudgetFailure(
	ctx: GenericEndpointContext,
	options: ResolvedFirstPartyAppsOptions,
	key: string,
): Promise<void> {
	if (!options.failureBudget) return;
	await ctx.context.adapter.incrementOne({
		model: BUDGET_MODEL,
		where: [
			{ field: "key", value: key },
			{ field: "failures", operator: "gt", value: 0 },
		],
		increment: { failures: -1 },
	});
}
