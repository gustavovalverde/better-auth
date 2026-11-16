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

const ISSUED_CREDENTIAL_MODEL = "oidc4vciIssuedCredential";
const ENTRY_PAGE_SIZE = 1000;

type StatusEntry = { statusListIndex: number; status: number };

/**
 * Random draws on one list before allocation treats it as crowded and moves
 * to the next list. All of them land on taken indices once the list is
 * roughly three quarters full.
 */
const RANDOM_INDEX_ATTEMPTS = 8;

/** Lists one allocation tries before it gives up. */
const LIST_ATTEMPTS = 4;

/** A uniform random integer in `[0, size)`, without modulo bias. */
function randomIndex(size: number) {
	const limit = Math.floor(2 ** 32 / size) * size;
	const value = new Uint32Array(1);
	do {
		crypto.getRandomValues(value);
	} while (value[0]! >= limit);
	return value[0]! % size;
}

/** The id of the `generation`th list: `listId`, then `listId-2`, `listId-3`. */
function generationListId(listId: string, generation: number) {
	return generation === 1 ? listId : `${listId}-${generation}`;
}

function parseGeneration(listId: string, statusListId: string) {
	if (statusListId === listId) return 1;
	const suffix = statusListId.startsWith(`${listId}-`)
		? statusListId.slice(listId.length + 1)
		: "";
	const generation = /^[1-9]\d*$/.test(suffix) ? Number(suffix) : 0;
	return generation >= 2 ? generation : 1;
}

/** The generation of the list the most recent credential went to. */
async function findCurrentGeneration(
	ctx: GenericEndpointContext,
	listId: string,
) {
	const [latest] = await ctx.context.adapter.findMany<{
		statusListId: string;
	}>({
		model: ISSUED_CREDENTIAL_MODEL,
		sortBy: { field: "createdAt", direction: "desc" },
		limit: 1,
	});
	return latest ? parseGeneration(listId, latest.statusListId) : 1;
}

async function isIndexAllocated(
	ctx: GenericEndpointContext,
	listId: string,
	index: number,
) {
	const entry = await ctx.context.adapter.findOne<{ id: string }>({
		model: ISSUED_CREDENTIAL_MODEL,
		where: [
			{ field: "statusListId", value: listId },
			{ field: "statusListIndex", value: index },
		],
	});
	return !!entry;
}

/**
 * Records an issued credential at a random free index of a status list and
 * returns the record. HAIP 1.0 §6.1 requires a unique, unpredictable index,
 * so the index is drawn at random; the unique (list, index) index refuses a
 * second record for one entry, which would let revoking one credential
 * revoke another. Once a list is crowded, credentials go to the next list,
 * so issuance never runs out of indices.
 */
export async function createStatusListEntry(
	ctx: GenericEndpointContext,
	options: Oidc4vciOptions,
	data: {
		userId: string;
		credentialConfigurationId: string;
		format: string;
	},
) {
	const { listId, size } = resolveStatusListOptions(options);
	const create = async (statusListId: string, index: number) => {
		try {
			return await ctx.context.adapter.create<
				Record<string, unknown>,
				{ id: string; statusListId: string; statusListIndex: number }
			>({
				model: ISSUED_CREDENTIAL_MODEL,
				data: {
					...data,
					statusListId,
					statusListIndex: index,
					status: 0,
					createdAt: new Date(),
				},
			});
		} catch (error) {
			// A concurrent issuance took the index first.
			if (await isIndexAllocated(ctx, statusListId, index)) return null;
			throw error;
		}
	};

	const firstGeneration = await findCurrentGeneration(ctx, listId);
	for (let offset = 0; offset < LIST_ATTEMPTS; offset++) {
		const statusListId = generationListId(listId, firstGeneration + offset);
		for (let attempt = 0; attempt < RANDOM_INDEX_ATTEMPTS; attempt++) {
			const index = randomIndex(size);
			if (await isIndexAllocated(ctx, statusListId, index)) continue;
			const entry = await create(statusListId, index);
			if (entry) return entry;
		}
	}
	throw new APIError("INTERNAL_SERVER_ERROR", {
		error: "server_error",
		error_description: "no status list has a free index",
	});
}

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
	// Unused indices read as valid, so the list's length and content do not
	// reveal how many credentials it holds.
	const statuses = Array.from(
		{ length: Math.max(highestIndex + 1, statusListOptions.size) },
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
