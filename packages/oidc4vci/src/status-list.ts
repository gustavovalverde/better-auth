import type { Where } from "@better-auth/core/db/adapter";
import { StatusList } from "@sd-jwt/jwt-status-list";
import { APIError } from "better-auth/api";
import type { JwtOptions } from "better-auth/plugins";
import type { Oidc4vciOptions } from "./types";
import { signSdJwtJwt } from "./utils/jwt";
import {
	getStatusListUri,
	resolveCredentialIssuer,
	resolveStatusListOptions,
} from "./utils/resolvers";

/**
 * Allocate the next status list index for a given list.
 *
 * Uses optimistic concurrency: reads the current max, returns max+1.
 * If a concurrent request races, the caller's subsequent insert will fail
 * on the unique (statusListId, statusListIndex) constraint and should retry.
 * We retry up to 3 times here to handle the common case automatically.
 */
export async function getNextStatusListIndex(
	ctx: {
		context: {
			adapter: {
				findMany: <T>(args: {
					model: string;
					where?: Where[];
					limit?: number;
					sortBy?: { field: string; direction: "asc" | "desc" };
				}) => Promise<T[]>;
			};
		};
	},
	statusListId: string,
) {
	const latest = await ctx.context.adapter.findMany<{
		statusListIndex?: number | null;
	}>({
		model: "oidc4vciIssuedCredential",
		where: [
			{
				field: "statusListId",
				value: statusListId,
			},
		],
		limit: 1,
		sortBy: {
			field: "statusListIndex",
			direction: "desc",
		},
	});
	const maxIndex = latest[0]?.statusListIndex;
	return typeof maxIndex === "number" ? maxIndex + 1 : 0;
}

export async function buildStatusListJwt(
	ctx: {
		context: {
			adapter: {
				findMany: <T>(args: { model: string; where?: Where[] }) => Promise<T[]>;
			};
			baseURL: string;
			getPlugin: (id: string) => unknown;
			secret: string;
		};
	},
	options: Oidc4vciOptions,
	listId: string,
) {
	const statusListOptions = resolveStatusListOptions(options);
	const entries = await ctx.context.adapter.findMany<{
		statusListIndex?: number | null;
		status?: number | null;
	}>({
		model: "oidc4vciIssuedCredential",
		where: [
			{
				field: "statusListId",
				value: listId,
			},
		],
	});
	const maxIndex = entries.reduce((max, entry) => {
		const index = entry.statusListIndex;
		return typeof index === "number" && index > max ? index : max;
	}, -1);
	const listSize = Math.max(maxIndex + 1, 0);
	const statuses = Array.from({ length: listSize }, () => 0);
	for (const entry of entries) {
		if (typeof entry.statusListIndex !== "number") continue;
		const statusValue = typeof entry.status === "number" ? entry.status : 0;
		statuses[entry.statusListIndex] = statusValue;
	}

	const list = new StatusList(statuses, statusListOptions.bits);
	const nowSeconds = Math.floor(Date.now() / 1000);
	const statusListUri = getStatusListUri(ctx, options, listId);
	const payload = {
		iss: resolveCredentialIssuer(ctx, options),
		sub: statusListUri,
		iat: nowSeconds,
		exp: nowSeconds + statusListOptions.ttlSeconds,
		ttl: statusListOptions.ttlSeconds,
		status_list: {
			bits: statusListOptions.bits,
			lst: list.compressStatusList(),
		},
	};

	const jwtPlugin = ctx.context.getPlugin("jwt") as {
		options?: JwtOptions;
	} | null;
	if (!jwtPlugin) {
		throw new APIError("INTERNAL_SERVER_ERROR", {
			message: "jwt plugin is required",
		});
	}

	let additionalHeaders: Record<string, unknown> | undefined;
	if (options.resolveCredentialHeaders) {
		const { key, alg } = await (
			await import("./utils/jwt")
		).getOrCreateSigningKey(ctx, jwtPlugin.options);
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
