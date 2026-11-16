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

async function fetchStatusList(issuer: Issuer, listId?: string) {
	const query = listId ? `?list_id=${listId}` : "";
	const res = await issuer.customFetchImpl(
		`${AUTH_BASE_URL}/oidc4vci/status-list${query}`,
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

async function statusReference(res: Response) {
	expect(res.status).toBe(200);
	const payload = decodeJwt(readCredential(await res.json()).split("~")[0]!);
	return (payload.status as { status_list: { idx: number; uri: string } })
		.status_list;
}

describe("oidc4vci - a crowded status list", async () => {
	const issuer = await createIssuer({ oidc4vci: { statusList: { size: 8 } } });

	it("moves issuance to a new list once the list is full", async () => {
		const { user } = await issuer.signInWithTestUser();
		const { adapter } = await issuer.auth.$context;
		const entry = (statusListId: string, statusListIndex: number) => ({
			model: "oidc4vciIssuedCredential",
			data: {
				userId: user.id,
				credentialConfigurationId: "earlier_config",
				format: "dc+sd-jwt",
				statusListId,
				statusListIndex,
				status: statusListIndex < 2 ? 1 : 0,
				createdAt: new Date(),
			},
		});
		for (let index = 0; index < 8; index++) {
			await adapter.create(entry("default", index));
		}

		const requests = [];
		for (let i = 0; i < 3; i++) requests.push(await prepareRequest(issuer));
		const references = await Promise.all(
			(await Promise.all(requests.map((request) => request.send()))).map(
				statusReference,
			),
		);
		const nextListUri = `${AUTH_BASE_URL}/oidc4vci/status-list?list_id=default-2`;
		for (const reference of references) {
			expect(reference.uri).toBe(nextListUri);
			expect(reference.idx).toBeLessThan(8);
		}
		expect(new Set(references.map((reference) => reference.idx)).size).toBe(3);

		// The full list still publishes its revoked entries.
		const full = await fetchStatusList(issuer);
		expect([0, 1, 2].map((i) => full.getStatus(i))).toEqual([1, 1, 0]);
		const next = await fetchStatusList(issuer, "default-2");
		expect(next.totalStatuses).toBe(8);
		// The schema's unique index refuses a second record for one entry.
		await expect(
			adapter.create(entry("default-2", references[0]!.idx)),
		).rejects.toThrow();
	});
});

describe("oidc4vci - valid credentials per user", async () => {
	const issuer = await createIssuer({
		oidc4vci: { maxValidCredentialsPerUser: 2 },
	});

	it("refuses a credential beyond the limit until one is revoked", async () => {
		const { tokens, user } = await issuer.issueAccessToken();
		const send = async () => {
			const { proofJwt } = await createJwtProof({
				nonce: await issuer.nonce(),
			});
			return issuer.requestCredential({
				accessToken: tokens.access_token,
				body: {
					credential_configuration_id: CONFIG_ID,
					proofs: { jwt: [proofJwt] },
				},
			});
		};
		expect((await send()).status).toBe(200);
		expect((await send()).status).toBe(200);

		const refused = await send();
		expect(refused.status).toBe(400);
		expect((await refused.json()).error).toBe("credential_request_denied");

		const { adapter } = await issuer.auth.$context;
		await adapter.update({
			model: "oidc4vciIssuedCredential",
			where: [{ field: "userId", value: user.id }],
			update: { status: 1 },
		});
		expect((await send()).status).toBe(200);
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

	it("rejects a status list size that is not an integer from 1 to 2^20", () => {
		for (const size of [0, -8, 1.5, 2 ** 20 + 1, 2 ** 33]) {
			expect(() =>
				oidc4vci({
					credentialConfigurations: [{ id: CONFIG_ID, vct: "urn:x" }],
					statusList: { size },
				}),
			).toThrow("statusList.size must be an integer from 1 to 1048576");
		}
		expect(() =>
			oidc4vci({
				credentialConfigurations: [{ id: CONFIG_ID, vct: "urn:x" }],
				statusList: { size: 2 ** 20 },
			}),
		).not.toThrow();
	});

	it("rejects a valid-credential limit that is not a positive integer", () => {
		for (const maxValidCredentialsPerUser of [0, -1, 2.5]) {
			expect(() =>
				oidc4vci({
					credentialConfigurations: [{ id: CONFIG_ID, vct: "urn:x" }],
					maxValidCredentialsPerUser,
				}),
			).toThrow("maxValidCredentialsPerUser must be a positive integer");
		}
	});
});
