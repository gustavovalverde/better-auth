import { twoFactor } from "better-auth/plugins";
import { describe, expect, it } from "vitest";
import type { FpaServer } from "./fpa-server";
import { createFpaServer, TEST_EMAIL, TEST_PASSWORD } from "./fpa-server";

async function respondSequence(
	server: FpaServer,
	clientId: string,
	passwords: string[],
	loginHint = TEST_EMAIL,
) {
	const { res } = await server.startPassword(clientId, {
		extra: { login_hint: loginHint },
	});
	const outcomes: Array<{ status: number; error?: string }> = [];
	for (const password of passwords) {
		const reply = await server.challenge({
			auth_session: res.body.auth_session,
			password,
		});
		outcomes.push({ status: reply.status, error: reply.body.error });
	}
	return outcomes;
}

async function budgetRows(server: FpaServer) {
	const ctx = await server.auth.$context;
	return ctx.adapter.findMany({ model: "firstPartyFailureBudget" }) as Promise<
		Array<{ key: string; failures: number; resetAt: Date }>
	>;
}

describe("first-party apps - failure budget (C1)", async () => {
	const server = await createFpaServer({
		plugin: { failureBudget: { maxFailures: 4, window: 900 } },
	});
	const client = await server.createClient();
	const wrong = "wrong-password";

	it("locks an account after failures across auth_sessions, silently", async () => {
		expect(
			await respondSequence(server, client.client_id, [wrong, wrong]),
		).toEqual([
			{ status: 400, error: "authentication_failed" },
			{ status: 400, error: "authentication_failed" },
		]);
		// Another spelling of the same address counts against the same account.
		await respondSequence(
			server,
			client.client_id,
			[wrong, wrong],
			"TEST@test.com",
		);
		const locked = await respondSequence(server, client.client_id, [
			TEST_PASSWORD,
		]);
		expect(locked).toEqual([{ status: 400, error: "authentication_failed" }]);
	});

	it("answers a locked account's correct and wrong credentials the same, ending with redirect_to_web", async () => {
		const correctFirst = await respondSequence(server, client.client_id, [
			TEST_PASSWORD,
			wrong,
			wrong,
		]);
		const allWrong = await respondSequence(server, client.client_id, [
			wrong,
			wrong,
			wrong,
		]);
		const allCorrect = await respondSequence(server, client.client_id, [
			TEST_PASSWORD,
			TEST_PASSWORD,
			TEST_PASSWORD,
		]);
		const expected = [
			{ status: 400, error: "authentication_failed" },
			{ status: 400, error: "authentication_failed" },
			{ status: 403, error: "redirect_to_web" },
		];
		expect(correctFirst).toEqual(expected);
		expect(allWrong).toEqual(expected);
		expect(allCorrect).toEqual(expected);
	});

	it("does not count a locked account's responses against its budget", async () => {
		const rows = await budgetRows(server);
		expect(rows.map((row) => row.failures)).toContain(4);
		expect(rows.every((row) => row.failures <= 4)).toBe(true);
	});

	it("unlocks after the window", async () => {
		const ctx = await server.auth.$context;
		for (const row of await budgetRows(server)) {
			await ctx.adapter.update({
				model: "firstPartyFailureBudget",
				where: [{ field: "key", value: row.key }],
				update: { resetAt: new Date(Date.now() - 1000) },
			});
		}
		const { final } = await server.signIn(client.client_id);
		expect(final.status).toBe(200);
	});

	it("locks an unknown email after the same number of failures", async () => {
		const hint = "ghost@example.com";
		await respondSequence(server, client.client_id, [wrong, wrong], hint);
		await respondSequence(
			server,
			client.client_id,
			[wrong, wrong, wrong],
			hint,
		);
		const ghost = (await budgetRows(server)).filter(
			(row) => new Date(row.resetAt) > new Date(),
		);
		expect(ghost.map((row) => row.failures)).toEqual([4]);
	});

	it("stores no email or user id in the budget table", async () => {
		const ctx = await server.auth.$context;
		const user = await ctx.internalAdapter.findUserByEmail(TEST_EMAIL);
		const serialized = JSON.stringify(await budgetRows(server));
		expect(serialized).not.toContain(TEST_EMAIL);
		expect(serialized).not.toContain("ghost@example.com");
		expect(serialized).not.toContain(user!.user.id);
	});
});

describe("first-party apps - two-factor", async () => {
	const server = await createFpaServer({ extraPlugins: [twoFactor()] });
	const client = await server.createClient();
	const enrolled = "enrolled@example.com";
	await server.auth.api.signUpEmail!({
		body: { email: enrolled, password: TEST_PASSWORD, name: "Enrolled" },
	});
	const ctx = await server.auth.$context;
	await ctx.internalAdapter.updateUserByEmail(enrolled, {
		twoFactorEnabled: true,
	});

	it("sends an enrolled user to the browser after a correct password, without a session or code", async () => {
		const sessionsBefore = (await server.sessionRows()).length;
		const { res } = await server.startPassword(client.client_id, {
			extra: { login_hint: enrolled },
		});
		const final = await server.challenge({
			auth_session: res.body.auth_session,
			password: TEST_PASSWORD,
		});
		expect(final.status).toBe(403);
		expect(final.body.error).toBe("redirect_to_web");
		expect(final.body.authorization_code).toBeUndefined();
		expect((await server.sessionRows()).length).toBe(sessionsBefore);
	});

	it("answers the initial and wrong-password requests the same for enrolled and other users", async () => {
		const shape = async (loginHint: string) => {
			const { res } = await server.startPassword(client.client_id, {
				extra: { login_hint: loginHint },
			});
			const failed = await server.challenge({
				auth_session: res.body.auth_session,
				password: "wrong-password",
			});
			return {
				initial: [res.status, Object.keys(res.body).sort()],
				failed: [
					failed.status,
					failed.body.error,
					Object.keys(failed.body).sort(),
				],
			};
		};
		expect(await shape(enrolled)).toEqual(await shape(TEST_EMAIL));
	});
});
