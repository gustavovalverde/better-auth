import type { GenericEndpointContext } from "@better-auth/core";
import type { Session, User } from "@better-auth/core/db";
import { base64Url } from "@better-auth/utils/base64";
import { createHMAC } from "@better-auth/utils/hmac";
import { symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";
import type {
	FirstPartyAuthorizationRequest,
	FirstPartyAuthSession,
	ResolvedFirstPartyAppsOptions,
} from "./types";

export const AUTH_SESSION_MODEL = "firstPartyAuthSession";

/** What a row keeps for its method between requests, encrypted at rest. */
export interface MethodState {
	state?: unknown;
	loginHint?: string;
	/** The non-plugin parameters of the request that started the method. */
	startParams: Record<string, unknown>;
}

/** The authorization a step-up grant held. */
export interface GrantCeiling {
	scope: string;
	resource?: string[];
	claims?: string;
}

/** 32 random bytes (draft §5.3.1 recommends at least 256 bits). */
function createHandle(): string {
	return base64Url.encode(crypto.getRandomValues(new Uint8Array(32)), {
		padding: false,
	});
}

/**
 * The stored form of a handle. A keyed hash rather than the provider's
 * `storeTokens` setting, so the raw handle is never stored whatever that
 * setting is.
 */
function hashHandle(
	ctx: GenericEndpointContext,
	handle: string,
): Promise<string> {
	return createHMAC("SHA-256", "base64urlnopad").sign(
		ctx.context.secret,
		`first-party-apps:auth-session:${handle}`,
	);
}

export async function findAuthSession(
	ctx: GenericEndpointContext,
	handle: string,
): Promise<FirstPartyAuthSession | null> {
	return ctx.context.adapter.findOne<FirstPartyAuthSession>({
		model: AUTH_SESSION_MODEL,
		where: [{ field: "authSession", value: await hashHandle(ctx, handle) }],
	});
}

export async function createAuthSession(
	ctx: GenericEndpointContext,
	data: Omit<
		FirstPartyAuthSession,
		"id" | "authSession" | "createdAt" | "updatedAt" | "attempts" | "failures"
	>,
): Promise<{ row: FirstPartyAuthSession; handle: string }> {
	const handle = createHandle();
	const now = new Date();
	const row = await ctx.context.adapter.create<
		Record<string, unknown>,
		FirstPartyAuthSession
	>({
		model: AUTH_SESSION_MODEL,
		data: {
			...data,
			authSession: await hashHandle(ctx, handle),
			failures: 0,
			attempts: 0,
			createdAt: now,
			updatedAt: now,
		},
	});
	return { row, handle };
}

export async function updateAuthSession(
	ctx: GenericEndpointContext,
	id: string,
	update: Partial<FirstPartyAuthSession>,
): Promise<void> {
	await ctx.context.adapter.update({
		model: AUTH_SESSION_MODEL,
		where: [{ field: "id", value: id }],
		update: { ...update, updatedAt: new Date() },
	});
}

/** Writes a new handle hash and returns the new handle (draft §5.3.1). */
export async function rotateAuthSessionHandle(
	ctx: GenericEndpointContext,
	id: string,
	update: Partial<FirstPartyAuthSession> = {},
): Promise<string> {
	const handle = createHandle();
	await updateAuthSession(ctx, id, {
		...update,
		authSession: await hashHandle(ctx, handle),
	});
	return handle;
}

export async function deleteAuthSession(
	ctx: GenericEndpointContext,
	id: string,
): Promise<void> {
	await ctx.context.adapter.delete({
		model: AUTH_SESSION_MODEL,
		where: [{ field: "id", value: id }],
	});
}

/**
 * Claims the row for this request: a single-use step guarded by the
 * `attempts` value the request read. Returns false when another request
 * claimed it first or a pending row used up `maxRequests`.
 */
export async function claimAuthSession(
	ctx: GenericEndpointContext,
	options: ResolvedFirstPartyAppsOptions,
	row: FirstPartyAuthSession,
): Promise<boolean> {
	if (
		row.state === "pending" &&
		row.attempts >= options.authSession.maxRequests
	) {
		return false;
	}
	const claimed = await ctx.context.adapter.incrementOne({
		model: AUTH_SESSION_MODEL,
		where: [
			{ field: "id", value: row.id },
			{ field: "attempts", value: row.attempts },
		],
		increment: { attempts: 1 },
		set: { updatedAt: new Date() },
	});
	if (!claimed) return false;
	row.attempts += 1;
	return true;
}

/**
 * Ends a row. Its backing session is deleted only when the plugin created
 * it for this flow (C2).
 */
export async function endAuthSession(
	ctx: GenericEndpointContext,
	row: FirstPartyAuthSession,
): Promise<void> {
	await deleteAuthSession(ctx, row.id);
	if (row.ownsSession && row.sessionId) {
		const session = await findSessionById(ctx, row.sessionId);
		if (session) await ctx.context.internalAdapter.deleteSession(session.token);
	}
}

async function findSessionById(
	ctx: GenericEndpointContext,
	sessionId: string,
): Promise<(Session & Record<string, unknown>) | null> {
	return ctx.context.adapter.findOne<Session & Record<string, unknown>>({
		model: "session",
		where: [{ field: "id", value: sessionId }],
	});
}

/** The session and user, when the session still lives. */
export async function findLiveSession(
	ctx: GenericEndpointContext,
	sessionId: string,
): Promise<{
	session: Session & Record<string, unknown>;
	user: User & Record<string, unknown>;
} | null> {
	const session = await findSessionById(ctx, sessionId);
	if (!session || new Date(session.expiresAt) <= new Date()) return null;
	const user = (await ctx.context.internalAdapter.findUserById(
		session.userId,
	)) as (User & Record<string, unknown>) | null;
	if (!user) return null;
	return { session, user };
}

export async function sealMethodState(
	ctx: GenericEndpointContext,
	value: MethodState,
): Promise<string> {
	return symmetricEncrypt({
		key: ctx.context.secretConfig,
		data: JSON.stringify(value),
	});
}

export async function openMethodState(
	ctx: GenericEndpointContext,
	sealed: string | null | undefined,
): Promise<MethodState | null> {
	if (!sealed) return null;
	try {
		return JSON.parse(
			await symmetricDecrypt({ key: ctx.context.secretConfig, data: sealed }),
		) as MethodState;
	} catch {
		return null;
	}
}

export function readRequest(
	row: FirstPartyAuthSession,
): FirstPartyAuthorizationRequest {
	return JSON.parse(row.request) as FirstPartyAuthorizationRequest;
}

export function readCeiling(row: FirstPartyAuthSession): GrantCeiling | null {
	return row.ceiling ? (JSON.parse(row.ceiling) as GrantCeiling) : null;
}

/**
 * When a row expires. An authenticated row follows its session, and a row
 * without a DPoP binding is a bearer credential, so it never outlives one
 * flow's lifetime.
 */
export function rowExpiry(
	options: ResolvedFirstPartyAppsOptions,
	input: { sessionExpiresAt?: Date; bound: boolean },
): Date {
	const flowEnd = new Date(Date.now() + options.authSession.expiresIn * 1000);
	if (!input.sessionExpiresAt) return flowEnd;
	const sessionEnd = new Date(input.sessionExpiresAt);
	return input.bound || sessionEnd < flowEnd ? sessionEnd : flowEnd;
}
