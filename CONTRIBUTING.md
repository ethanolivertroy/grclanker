# Contributing

grclanker is early. Small, specific fixes are welcome. [AGENTS.md](AGENTS.md) is the contributor contract: repository layout, commands, naming, how to add an integration, and what a pull request should include. Follow that file. This page is only the path into it.

## Set up a checkout

You need git, npm, and Node.js. The CLI needs Node.js 22.19 or newer (`cli/package.json`). The website needs Node.js 22.22 or newer (the root `package.json`).

```bash
git clone https://github.com/ethanolivertroy/grclanker.git
cd grclanker
npm --prefix cli ci
npm --prefix cli run build
node cli/bin/grclanker.js --help
```

For the website:

```bash
npm ci
npm run dev
```

## Check your change

- CLI change: `npm --prefix cli run test:cli`
- Website or docs change: `npm run build` and `npm run test:site`

Live smoke scripts, such as `npm --prefix cli run test:gws-ops:live`, skip when credentials or an external CLI are missing. A skip is the expected result on a machine without those credentials.

## Open a pull request

Use the pull request template. Say what a user can do after the change, and paste the validation commands you ran. Link the GitHub issue the change closes.

Do not commit tenant credentials, generated evidence bundles, or local workspace artifacts. `.gitignore` already covers common secrets such as `.env*`, `.okta.yaml`, `credentials.json`, `client_secret.json`, `*service-account*.json`, `export/`, and `oscal-workspace/`.

Security reports do not belong in a pull request or a public issue. Use [SECURITY.md](SECURITY.md).
