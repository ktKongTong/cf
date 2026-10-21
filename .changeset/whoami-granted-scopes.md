---
"cf": minor
---

Make interactive `cf auth whoami` output easier to scan by grouping granted OAuth permissions by namespace and highlighting write, sensitive, and non-default scopes. Preserve its existing JSON output, including the full raw scopes list, for scripts and non-interactive usage. No new flags or commands are introduced.
