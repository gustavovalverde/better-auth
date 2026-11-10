import { describe, expect, it } from "vitest";
import { AUTH_BASE_URL, createHaipServer, sha256 } from "./haip-server";

const PAR_URL = `${AUTH_BASE_URL}/oauth2/par`;
const REDIRECT_URI = "https://rp.example/callback";

describe("haip - pushed authorization requests", async () => {
	const server = await createHaipServer();

	async function createConfidentialClient() {
		const { headers } = await server.signInWithTestUser();
		const client = await server.createClient(headers, {
			redirect_uris: [REDIRECT_URI],
			token_endpoint_auth_method: "client_secret_post",
			grant_types: ["authorization_code"],
		});
		return { headers, client };
	}

	function authorizationParams(
		clientId: string,
		extra?: Record<string, string>,
	) {
		return {
			response_type: "code",
			client_id: clientId,
			redirect_uri: REDIRECT_URI,
			scope: "openid",
			state: "par-state",
			code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			code_challenge_method: "S256",
			...extra,
		};
	}

	it("authenticates the client and answers 201 with a request_uri", async () => {
		const { client } = await createConfidentialClient();
		const res = await server.postForm(
			PAR_URL,
			authorizationParams(client.client_id, {
				client_secret: client.client_secret!,
			}),
		);
		expect(res.status).toBe(201);
		expect(res.headers.get("cache-control")).toContain("no-store");
		const body = (await res.json()) as {
			request_uri: string;
			expires_in: number;
		};
		expect(body.request_uri).toMatch(/^urn:ietf:params:oauth:request_uri:/);
		expect(body.expires_in).toBe(60);
	});

	it("rejects a confidential client that does not authenticate", async () => {
		const { client } = await createConfidentialClient();
		const res = await server.postForm(
			PAR_URL,
			authorizationParams(client.client_id),
		);
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe("invalid_client");
	});

	it.each([
		[
			"request_uri",
			{ request_uri: "urn:ietf:params:oauth:request_uri:x" },
			"invalid_request",
		],
		[
			"an unregistered redirect_uri",
			{ redirect_uri: "https://attacker.example/cb" },
			"invalid_request",
		],
		[
			"a non-code response_type",
			{ response_type: "token" },
			"unsupported_response_type",
		],
	])("rejects %s", async (_label, extra, error) => {
		const { client } = await createConfidentialClient();
		const res = await server.postForm(
			PAR_URL,
			authorizationParams(client.client_id, {
				client_secret: client.client_secret!,
				...extra,
			}),
		);
		expect(res.status).toBe(400);
		expect((await res.json()).error).toBe(error);
	});

	it("does not persist client credentials with the pushed request", async () => {
		const { client } = await createConfidentialClient();
		await server.postForm(
			PAR_URL,
			authorizationParams(client.client_id, {
				client_secret: client.client_secret!,
			}),
		);
		const { adapter } = await server.auth.$context;
		const stored = await adapter.findMany<{ requestParams: string }>({
			model: "haipPushedRequest",
			where: [{ field: "clientId", value: client.client_id }],
		});
		expect(stored).toHaveLength(1);
		expect(JSON.parse(stored[0]!.requestParams)).not.toHaveProperty(
			"client_secret",
		);
	});

	it("redeems a request_uri once, for the client that pushed it", async () => {
		const { headers, client } = await createConfidentialClient();
		const verifier = crypto.randomUUID() + crypto.randomUUID();
		const res = await server.postForm(
			PAR_URL,
			authorizationParams(client.client_id, {
				client_secret: client.client_secret!,
				code_challenge: await sha256(verifier),
			}),
		);
		const { request_uri } = (await res.json()) as { request_uri: string };

		const authorize = (clientId: string) => {
			const url = new URL(`${AUTH_BASE_URL}/oauth2/authorize`);
			url.searchParams.set("request_uri", request_uri);
			url.searchParams.set("client_id", clientId);
			return server.customFetchImpl(url.toString(), {
				method: "GET",
				headers,
				redirect: "manual",
			});
		};

		const { client: other } = await createConfidentialClient();
		const foreign = await authorize(other.client_id);
		expect(foreign.headers.get("location") ?? "").not.toContain("code=");

		const first = await authorize(client.client_id);
		const location = first.headers.get("location") ?? "";
		expect(location).toContain("code=");
		expect(location).toContain("state=par-state");

		const replay = await authorize(client.client_id);
		expect(replay.headers.get("location") ?? "").toContain(
			"invalid_request_uri",
		);
	});

	it("matches loopback redirect URIs regardless of port", async () => {
		const { headers } = await server.signInWithTestUser();
		const client = await server.createClient(headers, {
			redirect_uris: ["http://127.0.0.1/callback"],
			grant_types: ["authorization_code"],
			application_type: "native",
		});
		const res = await server.postForm(
			PAR_URL,
			authorizationParams(client.client_id, {
				redirect_uri: "http://127.0.0.1:53124/callback",
			}),
		);
		expect(res.status).toBe(201);
	});
});

describe("haip - expired pushed requests", async () => {
	const server = await createHaipServer({ haip: { parExpiresInSeconds: 0 } });

	it("rejects an expired request_uri", async () => {
		const { headers } = await server.signInWithTestUser();
		const client = await server.createClient(headers, {
			redirect_uris: [REDIRECT_URI],
			grant_types: ["authorization_code"],
		});
		const res = await server.postForm(PAR_URL, {
			response_type: "code",
			client_id: client.client_id,
			redirect_uri: REDIRECT_URI,
			scope: "openid",
		});
		const { request_uri } = (await res.json()) as { request_uri: string };
		await new Promise((resolve) => setTimeout(resolve, 20));
		const url = new URL(`${AUTH_BASE_URL}/oauth2/authorize`);
		url.searchParams.set("request_uri", request_uri);
		url.searchParams.set("client_id", client.client_id);
		const authorize = await server.customFetchImpl(url.toString(), {
			method: "GET",
			headers,
			redirect: "manual",
		});
		expect(authorize.headers.get("location") ?? "").toContain(
			"invalid_request_uri",
		);
	});
});
