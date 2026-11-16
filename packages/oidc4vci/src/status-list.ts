import type { GenericEndpointContext } from "@better-auth/core";
import { StatusList } from "@owf/token-status-list";
import { APIError } from "better-auth/api";
import { base64url } from "jose";
import type { Oidc4vciOptions } from "./types";
import { getOrCreateSigningKey, signSdJwtJwt } from "./utils/jwt";
import {
	getStatusListUri,
	resolveCredentialIssuer,
	resolveStatusListOptions,
} from "./utils/resolvers";

const STATUS_LIST_MODEL = "oidc4vciStatusList";

type StatusListCounter = { id: string; listId: string; nextIndex: number };

/**
 * Allocates the next status list index for a list.
 *
 * The index comes from an atomic increment of a per-list counter, so
 * concurrent issuances never share an index (sharing one would make revoking
 * one credential revoke the other).
 */
export async function getNextStatusListIndex(
	ctx: GenericEndpointContext,
	statusListId: string,
) {
	const { adapter } = ctx.context;
	const where = [{ field: "listId", value: statusListId }];
	const existing = await adapter.findOne<StatusListCounter>({
		model: STATUS_LIST_MODEL,
		where,
	});
	if (!existing) {
		try {
			await adapter.create({
				model: STATUS_LIST_MODEL,
				data: { listId: statusListId, nextIndex: 0 },
			});
		} catch (error) {
			// A concurrent issuance created the counter first.
			const raced = await adapter.findOne<StatusListCounter>({
				model: STATUS_LIST_MODEL,
				where,
			});
			if (!raced) throw error;
		}
	}
	const updated = await adapter.incrementOne<StatusListCounter>({
		model: STATUS_LIST_MODEL,
		where,
		increment: { nextIndex: 1 },
	});
	if (!updated) {
		throw new APIError("INTERNAL_SERVER_ERROR", {
			message: "failed to allocate a status list index",
		});
	}
	return updated.nextIndex - 1;
}

const ISSUED_CREDENTIAL_MODEL = "oidc4vciIssuedCredential";
const ENTRY_PAGE_SIZE = 1000;

type StatusEntry = { statusListIndex: number; status: number };

/**
 * The entries of a list whose status is not valid. Adapters cap an unbounded
 * `findMany`, so the entries are read in pages.
 */
async function findChangedEntries(
	ctx: GenericEndpointContext,
	listId: string,
): Promise<StatusEntry[]> {
	const entries: StatusEntry[] = [];
	for (let offset = 0; ; offset += ENTRY_PAGE_SIZE) {
		const page = await ctx.context.adapter.findMany<StatusEntry>({
			model: ISSUED_CREDENTIAL_MODEL,
			where: [
				{ field: "statusListId", value: listId },
				{ field: "status", operator: "ne", value: 0 },
			],
			sortBy: { field: "statusListIndex", direction: "asc" },
			limit: ENTRY_PAGE_SIZE,
			offset,
		});
		entries.push(...page);
		if (page.length < ENTRY_PAGE_SIZE) return entries;
	}
}

async function findHighestIndex(ctx: GenericEndpointContext, listId: string) {
	const [highest] = await ctx.context.adapter.findMany<StatusEntry>({
		model: ISSUED_CREDENTIAL_MODEL,
		where: [{ field: "statusListId", value: listId }],
		sortBy: { field: "statusListIndex", direction: "desc" },
		limit: 1,
	});
	return highest?.statusListIndex ?? -1;
}

export async function buildStatusListJwt(
	ctx: GenericEndpointContext,
	options: Oidc4vciOptions,
	listId: string,
) {
	const statusListOptions = resolveStatusListOptions(options);
	const [changed, highestIndex] = await Promise.all([
		findChangedEntries(ctx, listId),
		findHighestIndex(ctx, listId),
	]);
	const statuses = Array.from(
		{ length: Math.max(highestIndex + 1, 1) },
		() => 0,
	);
	for (const entry of changed) {
		statuses[entry.statusListIndex] = entry.status;
	}

	const list = new StatusList(statuses, statusListOptions.bits);
	const nowSeconds = Math.floor(Date.now() / 1000);
	const payload = {
		iss: resolveCredentialIssuer(ctx, options),
		sub: getStatusListUri(ctx, options, listId),
		iat: nowSeconds,
		exp: nowSeconds + statusListOptions.ttlSeconds,
		ttl: statusListOptions.ttlSeconds,
		status_list: {
			bits: statusListOptions.bits,
			lst: base64url.encode(list.compressStatusListToBytes()),
		},
	};

	const jwtPlugin = ctx.context.getPlugin("jwt");
	if (!jwtPlugin) {
		throw new APIError("INTERNAL_SERVER_ERROR", {
			message: "jwt plugin is required",
		});
	}

	let additionalHeaders: Record<string, unknown> | undefined;
	if (options.resolveCredentialHeaders) {
		const { key, alg } = await getOrCreateSigningKey(ctx, jwtPlugin.options);
		additionalHeaders = await options.resolveCredentialHeaders({
			kid: key.id,
			alg,
			format: "statuslist+jwt",
			credentialConfigurationId: "__status_list__",
		});
	}

	return signSdJwtJwt(ctx, {
		payload,
		jwtOptions: jwtPlugin.options,
		header: {
			typ: "statuslist+jwt",
			...additionalHeaders,
		},
		applyDefaultClaims: false,
	});
}
