# Repository Guidelines

## Project Structure & Module Organization
`grclanker` has two main surfaces:

- `src/`: Astro marketing/docs site (`src/pages`, `src/content/docs`)
- `cli/`: TypeScript CLI runtime, prompts, extensions, scripts, and tests
- `specs/`: product and tool build specs, usually one `*-spec.md` per integration

Most contributor work lands in `cli/extensions/grc-tools/` for native tools, `cli/tests/` for regression coverage, and `cli/scripts/` for sync or live-smoke helpers.

## Build, Test, and Development Commands
- `npm run dev`: run the Astro site locally
- `npm run build`: build the Astro site
- `npm --prefix cli run build`: compile the CLI to `cli/dist/`
- `npm --prefix cli run dev`: run the CLI entrypoint with `tsx`
- `npm --prefix cli run test:cli`: build the CLI and run the full Node test suite
- `npm --prefix cli run sync:fedramp`: refresh generated FedRAMP docs/content from official sources

Live smoke scripts exist for integrations and intentionally skip when creds or external CLIs are missing, for example `npm --prefix cli run test:gws-ops:live`.

## Coding Style & Naming Conventions
Use ESM TypeScript and keep existing style consistent: 2-space indentation, semicolons, descriptive helper names, and small focused functions. New native tools should follow the existing `*_check_access`, `*_assess_*`, and `*_export_*` naming patterns. Keep prompts and site copy concise and grounded in shipped behavior.

## Adding an Integration
Integrations are designed so several can land in parallel with minimal overlap in shared files:

- Implement the tool family in one new file, `cli/extensions/grc-tools/<slug>.ts`, exporting `register<Name>Tools(pi)`.
- Register it with two one-line additive edits in `cli/extensions/grc-tools.ts`: the import, and an entry in `DOMAIN_TOOL_REGISTRARS` (alphabetical). The domain tool count is derived from that list.
- Add one alphabetical `["<slug>_", "<Display Name>"]` entry to `DOMAIN_GROUPS` in `cli/pi/tool-catalog.ts`; the catalog test fails if a domain tool has no group.
- Put tests in `cli/tests/<slug>.test.mjs`; `test:cli` picks up every `tests/*.test.mjs`, so do not edit the `test:cli` script.
- Add the live smoke script as `cli/scripts/<slug>-live-smoke.mjs` plus a `test:<slug>:live` entry in `cli/package.json`.
- Run `npm --prefix cli run sync:agent-sdk-tools` so every new tool gets its generated entry under `cli/agent-sdk/agent/tools/` (new files only). The Agent SDK and Flue tests derive their tool counts and write-tool list from the registry, so they need no edits; write tools are recognized by the verbs in `cli/agent-sdk/lib/effects.ts`. The `BASELINE_WRITE_TOOLS` list in `cli/tests/agent-sdk.test.mjs` is a floor of existing writers that changes only when one is intentionally renamed or removed, never for a new integration.
- If a new tool parameter looks like a credential (its name mentions key, token, secret, password, or similar) the Flue redaction test in `cli/tests/flue.test.mjs` fails until the name is either redacted by `cli/flue/redact.ts` or listed as reviewed-safe with a reason.
- Document the integration in `src/content/docs/docs/integrations/<slug>.md` (frontmatter `title` and `description`); the docs sidebar lists that folder automatically.
- Regenerate `src/content/docs/docs/tools/catalog.md` with `npm --prefix cli run sync:tool-catalog` only when you are not landing alongside other integration PRs, since every regeneration rewrites the shared counts.

## Testing Guidelines
Tests use Node’s built-in runner (`node --test`) with `.test.mjs` files in `cli/tests/`. Add targeted tests for every new tool, plus bundle/output-path checks when exporting files. Prefer mocked API coverage first, then add an optional `test:*:live` script for real-tenant smoke tests when relevant.

## Commit & Pull Request Guidelines
Recent history uses short imperative subjects like `Add Okta compliance assessment tools` and `Add Google Workspace CLI operator bridge`. Keep commits scoped to one feature or hardening pass. PRs should include:

- a clear summary of user-facing changes
- linked Linear issue(s)
- validation commands run
- screenshots only when site/docs UI changed

## Security & Configuration Tips
Never commit tenant credentials, generated evidence bundles, or local workspace artifacts. `.gitignore` already covers common secrets such as `.env*`, `.okta.yaml`, `credentials.json`, `client_secret.json`, `*service-account*.json`, `export/`, and `oscal-workspace/`. Prefer environment variables or local config files outside the repo for sensitive values.
