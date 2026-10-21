import { describe, expect, it } from "vite-plus/test";
import { groupGrantedScopes, renderGrantedScopes } from "../../../commands/auth/scope-display.js";

describe("OAuth scope presentation", () => {
	const defaults = ["workers:read", "workers:write", "dns.read", "openid"];

	it("groups by permission namespace and sorts scope names deterministically", () => {
		const groups = groupGrantedScopes(
			["workers:write", "openid", "dns.read", "workers:read", "dns.write"],
			defaults
		);
		expect(groups.map((group) => group.product)).toEqual([
			"DNS",
			"OAuth / other",
			"Workers",
		]);
		expect(
			groups.find((group) => group.product === "Workers")?.scopes.map(
				(scope) => scope.name
			)
		).toEqual(["workers:read", "workers:write"]);
		expect(groups.find((group) => group.product === "DNS")?.scopes[1]).toEqual({
			name: "dns.write",
			access: "write",
			source: "custom",
		});
	});

	it("highlights writing, sensitive, and non-default scopes", () => {
		const groups = groupGrantedScopes(
			["secrets-store.read", "dns.write", "dns.read"],
			defaults
		);
		const display = renderGrantedScopes(groups);
		expect(display).toContain("secrets-store.read [SENSITIVE, NON-DEFAULT]");
		expect(display).toContain("dns.write [WRITE, NON-DEFAULT]");
		expect(display).toContain("dns.read");
		expect(display).not.toContain("dns.read [");
	});

	it("handles no granted scopes without guessing products", () => {
		expect(groupGrantedScopes([], defaults)).toEqual([]);
		expect(renderGrantedScopes([])).toContain("0 across 0 groups");
	});

	it("preserves the exact raw scope names", () => {
		const scopes = [
			"access-acct.revoke",
			"hyperdrive-planetscale:setup",
			"workers_kv:write",
		];
		const grouped = groupGrantedScopes(scopes, defaults);
		expect(
			grouped.flatMap((group) => group.scopes.map((scope) => scope.name)).sort()
		).toEqual([...scopes].sort());
	});
});
