import type { GenericEndpointContext } from "@better-auth/core";
import { APIError } from "better-auth/api";
import type { JwtOptions } from "better-auth/plugins";
import type { User } from "better-auth/types";
import type { JWK } from "jose";
import { throwOidc4vciCredentialError } from "./error";
import { createStatusListEntry } from "./status-list";
import type {
	CredentialConfiguration,
	Oidc4vciCredentialFormat,
	Oidc4vciOptions,
} from "./types";
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
 * HAIP expect), allocates its status list entry, and records that entry
 * without the credential, which the issuer never reads again. The
 * credential carries no `sub`: SD-JWT VC makes it optional and needs no
 * binding between `sub` and `cnf`, and any identifier in it would let the
 * verifiers it reaches link the holder. `resolveClaims` may return an
 * issuer-assigned `sub` when a deployment needs one.
 */
export async function issueCredential(
	ctx: GenericEndpointContext,
	options: Oidc4vciOptions,
	input: {
		cfg: CredentialConfiguration;
		user: User;
		binding: HolderBinding;
		authorizationDetails: Record<string, unknown>[];
		credentialIdentifier?: string;
	},
) {
	const { cfg, user, binding } = input;
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

	const format = cfg.format ?? "dc+sd-jwt";
	const statusListId = resolveStatusListOptions(options).listId;
	const entry = await createStatusListEntry(ctx, options, {
		userId: user.id,
		credentialConfigurationId: cfg.id,
		format,
	});
	try {
		return await signCredential(ctx, options, {
			cfg,
			jwtOptions: jwtPlugin.options,
			format,
			claims,
			binding,
			requestedClaims,
			status: {
				idx: entry.statusListIndex,
				uri: getStatusListUri(ctx, options, statusListId),
			},
		});
	} catch (error) {
		await ctx.context.adapter.delete({
			model: "oidc4vciIssuedCredential",
			where: [{ field: "id", value: entry.id }],
		});
		throw error;
	}
}

async function signCredential(
	ctx: GenericEndpointContext,
	options: Oidc4vciOptions,
	input: {
		cfg: CredentialConfiguration;
		jwtOptions: JwtOptions | undefined;
		format: Oidc4vciCredentialFormat;
		claims: Record<string, unknown>;
		binding: HolderBinding;
		requestedClaims: ReturnType<typeof resolveRequestedClaims>;
		status: { idx: number; uri: string };
	},
) {
	const { cfg, jwtOptions, format, claims, binding, requestedClaims } = input;
	const now = Math.floor(Date.now() / 1000);
	// Resolved claims come first so they can never replace the registered
	// claims, holder binding, or status reference.
	const payload = {
		...claims,
		iss: resolveCredentialIssuer(ctx, options),
		vct: cfg.vct,
		iat: now,
		exp: now + (options.credentialExpiresInSeconds ?? 31536000),
		status: { status_list: input.status },
		cnf: {
			...binding.extraCnf,
			jwk: binding.jwk,
		},
	};

	const disclosureFrame = buildDisclosureFrame(cfg, payload, requestedClaims);
	const { key, alg } = await getOrCreateSigningKey(ctx, jwtOptions);
	const additionalHeaders = options.resolveCredentialHeaders
		? await options.resolveCredentialHeaders({
				kid: key.id,
				alg,
				format,
				credentialConfigurationId: cfg.id,
			})
		: undefined;
	return issueSdJwtCredential(ctx, {
		payload,
		jwtOptions,
		disclosureFrame,
		format,
		additionalHeaders,
		credentialSigner: options.credentialSigner,
	});
}
