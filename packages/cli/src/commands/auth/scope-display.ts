/**
 * Presentation-only metadata for granted OAuth scopes. The prefix of a scope
 * is its API permission namespace; it is the most reliable available grouping
 * without hard-coding the dashboard's evolving product taxonomy.
 */
export type ScopeAccess = "read" | "write" | "sensitive" | "other";

export interface ScopeDetail {
	name: string;
	access: ScopeAccess;
	/** "custom" means outside cf's default OAuth scope set, not a claim about how login was initiated. */
	source: "default" | "custom";
}

export interface ScopeGroup {
	product: string;
	scopes: ScopeDetail[];
}

function scopeAccess(scope: string): ScopeAccess {
	// Some read scopes expose personal data or secrets and warrant a warning too.
	if (
		/(?:^|[-_.:])(pii|secret|secrets|credential|credentials)(?:[-_.:]|$)/i.test(
			scope
		)
	) {
		return "sensitive";
	}
	if (
		/[.:](?:admin|revoke|purge|bind|write|edit|delete|create|setup)$/i.test(
			scope
		)
	) {
		return "write";
	}
	if (/[.:](?:read|metadata_read|run|list|view|evaluate)$/i.test(scope)) {
		return "read";
	}
	return "other";
}

function scopeProduct(scope: string): string {
	const separator = Math.max(scope.lastIndexOf("."), scope.lastIndexOf(":"));
	if (separator <= 0) {
		return "OAuth / other";
	}
	const namespace = scope.slice(0, separator);
	const acronyms = new Set([
		"ai", "api", "d1", "ddos", "dns", "ip", "kv", "mcp", "r2", "ssl",
		"ssh", "sso", "waf",
	]);
	return namespace
		.split(/[-_]/g)
		.map((part) =>
			acronyms.has(part.toLowerCase())
				? part.toUpperCase()
				: part.slice(0, 1).toUpperCase() + part.slice(1)
		)
		.join(" ");
}

/** Group deterministically without altering or losing the original granted scope strings. */
export function groupGrantedScopes(
	scopes: readonly string[],
	defaultScopeKeys: readonly string[]
): ScopeGroup[] {
	const defaults = new Set(defaultScopeKeys);
	const products = new Map<string, ScopeDetail[]>();

	for (const name of scopes) {
		const product = scopeProduct(name);
		const group = products.get(product) ?? [];
		group.push({
			name,
			access: scopeAccess(name),
			source: defaults.has(name) ? "default" : "custom",
		});
		products.set(product, group);
	}

	return [...products.entries()]
		.sort(([left], [right]) => left.localeCompare(right))
		.map(([product, details]) => ({
			product,
			scopes: details.sort((left, right) => left.name.localeCompare(right.name)),
		}));
}

/** Only used on interactive stdout. Pipes always receive structured JSON. */
export function renderGrantedScopes(groups: readonly ScopeGroup[]): string {
	const count = groups.reduce((total, group) => total + group.scopes.length, 0);
	const lines = [
		"Granted OAuth scopes: " + count + " across " + groups.length + " groups",
	];

	for (const group of groups) {
		lines.push("", group.product + " (" + group.scopes.length + ")");
		for (const scope of group.scopes) {
			const labels: string[] = [];
			if (scope.access === "write") labels.push("WRITE");
			if (scope.access === "sensitive") labels.push("SENSITIVE");
			if (scope.source === "custom") labels.push("NON-DEFAULT");
			lines.push(
				"  " + scope.name + (labels.length ? " [" + labels.join(", ") + "]" : "")
			);
		}
	}

	lines.push("", "NON-DEFAULT = not in cf's default requested scope set.");
	return lines.join("\n");
}
