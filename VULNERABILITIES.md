# Known Vulnerabilities — vulnerable-sample-app

This file documents the intentional vulnerabilities for agent testing.

| Package | Pinned Version | CVE(s) | Issue | Safe Version |
|---------|---------------|--------|-------|-------------|
| `lodash` | 4.17.20 | CVE-2021-23337, CVE-2020-28500 | Prototype pollution via `_.merge`, command injection via `_.template` | ≥ 4.17.21 |
| `jsonwebtoken` | 8.5.1 | CVE-2022-23529, CVE-2022-23539 | Algorithm confusion / secret injection | ≥ 9.0.0 |
| `serialize-javascript` | 6.0.0 | CVE-2023-22025 | XSS via unsafe serialization | ≥ 6.0.1 |
| `semver` | 7.3.7 | CVE-2022-25883 | ReDoS via crafted version string | ≥ 7.5.2 |
| `tough-cookie` | 4.1.2 | CVE-2023-26136 | Prototype pollution | ≥ 4.1.3 |
| `word-wrap` | 1.2.3 | CVE-2023-26115 | ReDoS | ≥ 1.2.4 |
| `xml2js` | 0.4.23 | CVE-2023-0842 | Prototype pollution | ≥ 0.5.0 |
| `axios` | 1.3.4 | CVE-2023-45857 | CSRF / credential leak via cross-origin redirect | ≥ 1.6.0 |
| `multer` | 1.4.4 | CVE-2022-24434 | Path traversal in filename handling | ≥ 1.4.5-lts.1 |

## Notes for agent testing
- `lodash`, `semver`, `tough-cookie`, `word-wrap`, `xml2js` are **direct** dependencies
- `jsonwebtoken` and `serialize-javascript` require version bumps with API-compatible replacements
- `multer` safe fix is the LTS patch release `1.4.5-lts.1`, not `2.x` (breaking)
- After patching `package.json`, the agent should regenerate `pnpm-lock.yaml` via `pnpm install --no-frozen-lockfile`
