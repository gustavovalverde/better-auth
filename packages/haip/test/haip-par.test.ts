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

	it("advertises the provider's pushed authorization request endpoint", async () => {
		const metadata = (await server.auth.api.getOAuthServerConfig()) as Record<
			string,
			unknown
		>;
		expect(metadata.pushed_authorization_request_endpoint).toBe(PAR_URL);
		expect(metadata.require_pushed_authorization_requests).toBe(true);
	});

	it("redeems a pushed request_uri once at the authorize endpoint", async () => {
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

		const authorize = () => {
			const url = new URL(`${AUTH_BASE_URL}/oauth2/authorize`);
			url.searchParams.set("request_uri", request_uri);
			url.searchParams.set("client_id", client.client_id);
			return server.customFetchImpl(url.toString(), {
				method: "GET",
				headers,
				redirect: "manual",
			});
		};

		const first = await authorize();
		const location = first.headers.get("location") ?? "";
		expect(location).toContain("code=");
		expect(location).toContain("state=par-state");

		const replay = await authorize();
		expect(replay.headers.get("location") ?? "").toContain(
			"invalid_request_uri",
		);
	});
});
