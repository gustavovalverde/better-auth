import { getListFromStatusListJWT } from "@owf/token-status-list";
import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import { oidc4vci } from "../src";
import {
	AUTH_BASE_URL,
	CONFIG_ID,
	createIssuer,
	createJwtProof,
	readCredential,
} from "./issuer";

type Issuer = Awaited<ReturnType<typeof createIssuer>>;

async function prepareRequest(issuer: Issuer) {
	const { tokens, user } = await issuer.issueAccessToken();
	const { proofJwt } = await createJwtProof({ nonce: await issuer.nonce() });
	return {
		user,
		send: () =>
			issuer.requestCredential({
				accessToken: tokens.access_token,
				body: {
					credential_configuration_id: CONFIG_ID,
					proofs: { jwt: [proofJwt] },
				},
			}),
	};
}

async function statusIndex(res: Response) {
	expect(res.status).toBe(200);
	const payload = decodeJwt(readCredential(await res.json()).split("~")[0]!);
	return (payload.status as { status_list: { idx: number } }).status_list.idx;
}

async function fetchStatusList(issuer: Issuer) {
	const res = await issuer.customFetchImpl(
		`${AUTH_BASE_URL}/oidc4vci/status-list`,
		{ method: "GET" },
	);
	return getListFromStatusListJWT(await res.text());
}

describe("oidc4vci - status list indices", async () => {
	const issuer = await createIssuer();

	it("draws each credential's index at random from the whole list", async () => {
		const requests = [];
		for (let i = 0; i < 4; i++) requests.push(await prepareRequest(issuer));
		const indices = [];
		for (const request of requests) {
			indices.push(await statusIndex(await request.send()));
		}

		expect(new Set(indices).size).toBe(4);
		for (const index of indices) {
			expect(index).toBeGreaterThanOrEqual(0);
			expect(index).toBeLessThan(131072);
		}
		// Sequential allocation would give 0, 1, 2, and 3.
		expect(Math.max(...indices)).toBeGreaterThan(64);
	});

	it("publishes every index of the list, used or not", async () => {
		const list = await fetchStatusList(issuer);
		expect(list.totalStatuses).toBe(131072);
	});
});

describe("oidc4vci - a crowded status list", async () => {
	const issuer = await createIssuer({ oidc4vci: { statusList: { size: 8 } } });

	it("gives every free index out once, then refuses", async () => {
		const { user } = await issuer.signInWithTestUser();
		const { adapter } = await issuer.auth.$context;
		// Indices an earlier sequential allocation used.
		for (const statusListIndex of [0, 1]) {
			await adapter.create({
				model: "oidc4vciIssuedCredential",
				data: {
					userId: user.id,
					credentialConfigurationId: CONFIG_ID,
					format: "dc+sd-jwt",
					statusListId: "default",
					statusListIndex,
					status: 1,
					createdAt: new Date(),
				},
			});
		}

		const requests = [];
		for (let i = 0; i < 7; i++) requests.push(await prepareRequest(issuer));
		const responses = await Promise.all(
			requests.slice(0, 6).map((request) => request.send()),
		);
		const indices = await Promise.all(responses.map(statusIndex));
		expect(indices.sort()).toEqual([2, 3, 4, 5, 6, 7]);

		const full = await requests[6]!.send();
		expect(full.status).toBe(500);
		expect(await full.json()).toMatchObject({
			error: "server_error",
			error_description: "the status list has no free index",
		});

		const list = await fetchStatusList(issuer);
		expect([0, 1, 2, 3, 4, 5, 6, 7].map((i) => list.getStatus(i))).toEqual([
			1, 1, 0, 0, 0, 0, 0, 0,
		]);
		// The schema's unique index refuses a second record for one entry.
		await expect(
			adapter.create({
				model: "oidc4vciIssuedCredential",
				data: {
					userId: user.id,
					credentialConfigurationId: CONFIG_ID,
					format: "dc+sd-jwt",
					statusListId: "default",
					statusListIndex: indices[0]!,
					status: 0,
					createdAt: new Date(),
				},
			}),
		).rejects.toThrow();
	});
});

describe("oidc4vci - status list entries", async () => {
	const issuer = await createIssuer({
		oidc4vci: {
			credentialSigner: () => {
				throw new Error("signer unavailable");
			},
		},
	});

	it("releases the entry of a credential that was never signed", async () => {
		const request = await prepareRequest(issuer);
		const res = await request.send();
		expect(res.status).toBe(500);

		const { adapter } = await issuer.auth.$context;
		const records = await adapter.findMany({
			model: "oidc4vciIssuedCredential",
			where: [{ field: "userId", value: request.user.id }],
		});
		expect(records).toHaveLength(0);
	});

	it("rejects a status list size that is not a positive integer", () => {
		for (const size of [0, -8, 1.5]) {
			expect(() =>
				oidc4vci({
					credentialConfigurations: [{ id: CONFIG_ID, vct: "urn:x" }],
					statusList: { size },
				}),
			).toThrow("statusList.size must be a positive integer");
		}
	});
});
