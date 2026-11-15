import type { GenericEndpointContext } from "@better-auth/core";
import { describe, expectTypeOf, it } from "vitest";
import type {
	FirstPartyAppsOptions,
	FirstPartyAuthorizationDecision,
	FirstPartyMethod,
	FirstPartyMethodRespondResult,
	FirstPartyMethodStartInput,
	FirstPartyMethodStartResult,
	FirstPartyStepUpInput,
} from "../src";
import {
	challengeFirstPartyStepUp,
	firstPartyApps,
	passwordMethod,
} from "../src";

describe("public first-party-apps types", () => {
	it("types the canonical setup", () => {
		const plugin = firstPartyApps({
			isFirstPartyClient: ({ client }) => client.clientId === "mobile-app",
			methods: [passwordMethod()],
		});
		expectTypeOf(plugin.id).toEqualTypeOf<"first-party-apps">();
		expectTypeOf(passwordMethod()).toEqualTypeOf<FirstPartyMethod>();
		expectTypeOf<FirstPartyAppsOptions["isFirstPartyClient"]>()
			.parameter(0)
			.toHaveProperty("client");
		expectTypeOf<FirstPartyAppsOptions["failureBudget"]>().toEqualTypeOf<
			{ maxFailures?: number; window?: number } | false | undefined
		>();
	});

	it("types the method interface and its results", () => {
		expectTypeOf<FirstPartyMethodStartInput["previous"]>().toEqualTypeOf<
			{ state: unknown } | undefined
		>();
		expectTypeOf<FirstPartyMethodStartResult["type"]>().toEqualTypeOf<
			"challenge" | "redirect_to_web"
		>();
		expectTypeOf<FirstPartyMethodRespondResult["type"]>().toEqualTypeOf<
			"challenge" | "authenticated" | "redirect_to_web" | "failed"
		>();
		expectTypeOf<
			Extract<FirstPartyMethodStartResult, { type: "challenge" }>["userId"]
		>().toEqualTypeOf<string | null>();
	});

	it("types the policy decision", () => {
		expectTypeOf<
			Exclude<FirstPartyAuthorizationDecision, void | undefined>["type"]
		>().toEqualTypeOf<
			"insufficient_authorization" | "reauthenticate" | "redirect_to_web"
		>();
	});

	it("requires the step-up helper's security facts", () => {
		expectTypeOf<FirstPartyStepUpInput["dpopJkt"]>().toEqualTypeOf<
			string | null
		>();
		expectTypeOf<FirstPartyStepUpInput["sessionId"]>().toEqualTypeOf<
			string | null
		>();
		expectTypeOf(challengeFirstPartyStepUp).parameters.toEqualTypeOf<
			[GenericEndpointContext, FirstPartyStepUpInput]
		>();
		expectTypeOf(challengeFirstPartyStepUp).returns.toEqualTypeOf<
			Promise<void>
		>();
	});
});
