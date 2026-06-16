import { createHash, randomBytes } from "node:crypto";
import {
	clientAuthenticationAnonymous,
	HashAlgorithm,
} from "@openid4vc/oauth2";
import {
	Openid4vciClient,
	Openid4vciIssuer,
	setGlobalConfig,
} from "@openid4vc/openid4vci";

let allowInsecureUrlsSet = false;

function ensureAllowInsecureUrls() {
	if (allowInsecureUrlsSet) return;
	setGlobalConfig({ allowInsecureUrls: true });
	allowInsecureUrlsSet = true;
}

function createHashCallback() {
	return async (data: Uint8Array, alg: HashAlgorithm) => {
		const algorithm =
			alg === HashAlgorithm.Sha256
				? "sha256"
				: alg === HashAlgorithm.Sha384
					? "sha384"
					: "sha512";
		return new Uint8Array(createHash(algorithm).update(data).digest());
	};
}

function createSignJwtCallback() {
	return async () => {
		throw new Error("signJwt callback is not implemented for tests");
	};
}

function createVerifyJwtCallback() {
	return async () => ({ verified: false as const });
}

function createGenerateRandomCallback() {
	return async (byteLength: number) => randomBytes(byteLength);
}

export function createOpenid4vciTestIssuer() {
	ensureAllowInsecureUrls();
	return new Openid4vciIssuer({
		callbacks: {
			hash: createHashCallback(),
			signJwt: createSignJwtCallback(),
			verifyJwt: createVerifyJwtCallback(),
			generateRandom: createGenerateRandomCallback(),
			clientAuthentication: clientAuthenticationAnonymous(),
		},
	});
}

export function createOpenid4vciTestClient(fetchImpl: typeof fetch) {
	ensureAllowInsecureUrls();
	return new Openid4vciClient({
		callbacks: {
			fetch: fetchImpl,
			hash: createHashCallback(),
			signJwt: createSignJwtCallback(),
			generateRandom: createGenerateRandomCallback(),
			clientAuthentication: clientAuthenticationAnonymous(),
		},
	});
}
