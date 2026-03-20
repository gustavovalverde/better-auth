import { parseOpenid4VpAuthorizationResponsePayload } from "@openid4vc/openid4vp";
import { describe, expect, it } from "vitest";

describe("oidc4vp - openid4vc-ts conformance", () => {
	it("parses a full authorization response payload", () => {
		const payload = {
			state: "state-123",
			vp_token: ["vp.jwt.one", "vp.jwt.two"],
			presentation_submission: {
				id: "submission-1",
				definition_id: "definition-1",
				descriptor_map: [],
			},
			access_token: "access-token",
			token_type: "bearer",
			expires_in: 300,
			refresh_token: "refresh-token",
			id_token: "id-token",
		};

		const parsed = parseOpenid4VpAuthorizationResponsePayload(payload);
		expect(parsed.vp_token).toEqual(payload.vp_token);
		expect(parsed.presentation_submission).toEqual(
			payload.presentation_submission,
		);
	});
});
