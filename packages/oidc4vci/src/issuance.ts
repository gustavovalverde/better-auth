import type { GenericEndpointContext } from "@better-auth/core";
import { APIError } from "better-auth/api";
import type { User } from "better-auth/types";
import type { JWK } from "jose";
import { throwOidc4vciCredentialError } from "./error";
import { getNextStatusListIndex } from "./status-list";
import type { CredentialConfiguration, Oidc4vciOptions } from "./types";
import {
	filterClaimsForRequest,
	resolveClaimsForUser,
	resolveRequestedClaims,
} from "./utils/claims";
import { getOrCreateSigningKey } from "./utils/jwt";
import {
	getStatusListUri,
	resolveCredentialIssuer,
	resolveStatusListOptions,
} from "./utils/resolvers";
import { buildDisclosureFrame, issueSdJwtCredential } from "./utils/sd-jwt";

export type HolderBinding = {
	jwk: JWK;
	extraCnf?: Record<string, unknown>;
};

/**
 * Issues one SD-JWT VC bound to the holder key (`cnf.jwk`, as SD-JWT VC and
 * HAIP expect), allocates its status list entry, and records it.
 */
export async function issueCredential(
	ctx: GenericEndpointContext,
	options: Oidc4vciOptions,
	input: {
		cfg: CredentialConfiguration;
		user: User;
		subject: string;
		binding: HolderBinding;
		authorizationDetails: Record<string, unknown>[];
		credentialIdentifier?: string;
	},
) {
	const { cfg, user, subject, binding } = input;
	const jwtPlugin = ctx.context.getPlugin("jwt");
	if (!jwtPlugin) {
		throw new APIError("INTERNAL_SERVER_ERROR", {
			message: "jwt plugin is required",
		});
	}

	const requestedClaims = resolveRequestedClaims(input.authorizationDetails, {
		credentialConfigurationId: cfg.id,
		credentialIdentifier: input.credentialIdentifier,
	});
	const resolvedClaims = await resolveClaimsForUser(options, {
		user,
		credentialConfigurationId: cfg.id,
		credentialIdentifier: input.credentialIdentifier,
		requestedClaims,
	});
	const { claims, missingMandatory } = filterClaimsForRequest(
		resolvedClaims,
		requestedClaims,
	);
	if (missingMandatory.length) {
		throwOidc4vciCredentialError(
			"credential_request_denied",
			`missing required claims: ${missingMandatory.join(", ")}`,
		);
	}

	const statusListId = resolveStatusListOptions(options).listId;
	const statusListIndex = await getNextStatusListIndex(ctx, statusListId);
	const now = Math.floor(Date.now() / 1000);
	const format = cfg.format ?? "dc+sd-jwt";
	// Resolved claims come first so they can never replace the registered
	// claims, holder binding, or status reference.
	const payload = {
		...claims,
		iss: resolveCredentialIssuer(ctx, options),
		sub: subject,
		vct: cfg.vct,
		iat: now,
		exp: now + (options.credentialExpiresInSeconds ?? 31536000),
		status: {
			status_list: {
				idx: statusListIndex,
				uri: getStatusListUri(ctx, options, statusListId),
			},
		},
		cnf: {
			...binding.extraCnf,
			jwk: binding.jwk,
		},
	};

	const disclosureFrame = buildDisclosureFrame(cfg, payload, requestedClaims);
	const { key, alg } = await getOrCreateSigningKey(ctx, jwtPlugin.options);
	const additionalHeaders = options.resolveCredentialHeaders
		? await options.resolveCredentialHeaders({
				kid: key.id,
				alg,
				format,
				credentialConfigurationId: cfg.id,
			})
		: undefined;
	const credential = await issueSdJwtCredential(ctx, {
		payload,
		jwtOptions: jwtPlugin.options,
		disclosureFrame,
		format,
		additionalHeaders,
		credentialSigner: options.credentialSigner,
	});

	await ctx.context.adapter.create({
		model: "oidc4vciIssuedCredential",
		data: {
			userId: user.id,
			credentialConfigurationId: cfg.id,
			format,
			statusListId,
			statusListIndex,
			status: 0,
			credential,
			createdAt: new Date(),
		},
	});

	return credential;
}
