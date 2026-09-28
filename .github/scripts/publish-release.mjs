#!/usr/bin/env node
// Create-only GitHub release publisher for release-bundles.yml.
//
// Every step addresses the single release ID this script created. Any HTTP status
// other than the one expected, any transport error, and any redirect stops the run.
import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const API_VERSION = "2022-11-28";
const SUMS_NAME = "SHA256SUMS.txt";
const TAG_PATTERN = /^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$/;
const REPO_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]*)\/[A-Za-z0-9._-]+$/;
const COMMIT_PATTERN = /^[0-9a-f]{40}$/;
const SUMS_LINE_PATTERN = /^([0-9a-f]{64}) {2}([A-Za-z0-9][A-Za-z0-9._-]*)$/;
const MAX_PAGES = 50;
const MAX_TAG_DEPTH = 5;

export class ReleaseError extends Error {}

function fail(message) {
  throw new ReleaseError(message);
}

export function validateTag(tag) {
  if (typeof tag !== "string" || !TAG_PATTERN.test(tag)) {
    fail(`Tag ${JSON.stringify(tag)} is not a vMAJOR.MINOR.PATCH[-PRERELEASE] version`);
  }
  return tag;
}

export function validateRepo(repo) {
  if (typeof repo !== "string" || !REPO_PATTERN.test(repo)) {
    fail(`Repository ${JSON.stringify(repo)} is not an owner/name pair`);
  }
  return repo;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function loadReleaseAssets(dir) {
  const sumsBytes = readFileSync(join(dir, SUMS_NAME));
  const lines = sumsBytes.toString("utf8").split("\n");
  if (lines.pop() !== "") {
    fail(`${SUMS_NAME} must end with a newline`);
  }
  const assets = [];
  for (const line of lines) {
    const match = SUMS_LINE_PATTERN.exec(line);
    if (!match) {
      fail(`Malformed ${SUMS_NAME} line: ${JSON.stringify(line)}`);
    }
    const [, digest, name] = match;
    if (name === SUMS_NAME || assets.some((asset) => asset.name === name)) {
      fail(`Duplicate or reserved name in ${SUMS_NAME}: ${name}`);
    }
    assets.push({ name, digest, path: join(dir, name) });
  }
  if (assets.length === 0) {
    fail(`${SUMS_NAME} lists no archives`);
  }

  const present = readdirSync(dir).sort();
  const expected = [...assets.map((asset) => asset.name), SUMS_NAME].sort();
  if (present.join("\n") !== expected.join("\n")) {
    fail(`Asset directory holds [${present.join(", ")}], expected exactly [${expected.join(", ")}]`);
  }

  for (const asset of assets) {
    const stats = lstatSync(asset.path);
    if (!stats.isFile()) {
      fail(`${asset.name} is not a regular file`);
    }
    const actual = sha256(readFileSync(asset.path));
    if (actual !== asset.digest) {
      fail(`${asset.name} hashes to ${actual}, but ${SUMS_NAME} lists ${asset.digest}`);
    }
    asset.size = stats.size;
  }
  assets.push({ name: SUMS_NAME, digest: sha256(sumsBytes), path: join(dir, SUMS_NAME), size: sumsBytes.length });
  return assets;
}

function uploadOriginFor(api) {
  return api.hostname === "api.github.com" ? "https://uploads.github.com" : `${api.origin}/api/uploads`;
}

function nextLink(header) {
  if (!header) {
    return null;
  }
  for (const part of header.split(",")) {
    const match = /^\s*<([^>]+)>\s*;\s*rel="next"\s*$/.exec(part);
    if (match) {
      return match[1];
    }
  }
  return null;
}

function describeBody(data) {
  const message = data && typeof data === "object" && typeof data.message === "string" ? data.message : "";
  return message ? `: ${message.slice(0, 200)}` : "";
}

export function createGitHubClient({ apiUrl = "https://api.github.com", token, repo, fetchImpl = fetch }) {
  if (!token) {
    fail("GH_TOKEN is not set");
  }
  validateRepo(repo);
  const api = new URL(apiUrl);
  if (api.protocol !== "https:") {
    fail(`API URL must use https: ${api.origin}`);
  }
  const apiPrefix = api.pathname.replace(/\/+$/, "");
  const uploadBase = new URL(uploadOriginFor(api));
  const [owner, name] = repo.split("/");
  const repoPath = `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`;

  const apiUrlFor = (path) => new URL(`${apiPrefix}${repoPath}${path}`, api.origin);

  async function request(method, url, { expect, json, bytes } = {}) {
    const expected = Array.isArray(expect) ? expect : [expect];
    const headers = {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "User-Agent": "grclanker-release-bundles",
      "X-GitHub-Api-Version": API_VERSION,
    };
    let body;
    if (json !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(json);
    } else if (bytes !== undefined) {
      headers["Content-Type"] = "application/octet-stream";
      body = bytes;
    }

    let response;
    try {
      response = await fetchImpl(url, { method, headers, body, redirect: "error" });
    } catch (error) {
      fail(`${method} ${url.pathname} failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    const text = await response.text();
    let data = null;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        if (expected.includes(response.status)) {
          fail(`${method} ${url.pathname} returned a non-JSON body`);
        }
      }
    }
    if (!expected.includes(response.status)) {
      fail(`${method} ${url.pathname} returned HTTP ${response.status}, expected ${expected.join(" or ")}${describeBody(data)}`);
    }
    return { status: response.status, data, headers: response.headers };
  }

  async function paginate(firstUrl) {
    const items = [];
    let url = firstUrl;
    for (let page = 0; url; page += 1) {
      if (page >= MAX_PAGES) {
        fail(`Stopped paginating ${firstUrl.pathname} after ${MAX_PAGES} pages`);
      }
      const { data, headers } = await request("GET", url, { expect: 200 });
      if (!Array.isArray(data)) {
        fail(`GET ${url.pathname} did not return a list`);
      }
      items.push(...data);
      const next = nextLink(headers.get("link"));
      if (!next) {
        break;
      }
      url = new URL(next);
      if (url.origin !== api.origin || !url.pathname.startsWith(`${apiPrefix}${repoPath}/`)) {
        fail(`Pagination link for ${firstUrl.pathname} points outside the repository API`);
      }
    }
    return items;
  }

  return {
    async releaseForTag(tag) {
      const { status, data } = await request("GET", apiUrlFor(`/releases/tags/${encodeURIComponent(tag)}`), {
        expect: [200, 404],
      });
      return status === 404 ? null : data;
    },
    async listReleasesForTag(tag) {
      const url = apiUrlFor("/releases");
      url.searchParams.set("per_page", "100");
      return (await paginate(url)).filter((release) => release && release.tag_name === tag);
    },
    async tagCommitChain(tag) {
      const { data } = await request("GET", apiUrlFor(`/git/ref/tags/${encodeURIComponent(tag)}`), { expect: 200 });
      if (!data || Array.isArray(data) || data.ref !== `refs/tags/${tag}` || !data.object) {
        fail(`refs/tags/${tag} did not resolve to exactly one ref`);
      }
      const chain = [];
      let object = data.object;
      for (let depth = 0; ; depth += 1) {
        if (!COMMIT_PATTERN.test(object.sha ?? "")) {
          fail(`refs/tags/${tag} points at a malformed object`);
        }
        chain.push(object.sha);
        if (object.type === "commit") {
          return chain;
        }
        if (object.type !== "tag" || depth >= MAX_TAG_DEPTH) {
          fail(`refs/tags/${tag} does not resolve to a commit`);
        }
        const { data: tagObject } = await request("GET", apiUrlFor(`/git/tags/${object.sha}`), { expect: 200 });
        object = tagObject?.object ?? {};
      }
    },
    async createDraft({ tag, sha, name, notes }) {
      // target_commitish only matters if the tag vanished since preflight; GitHub would
      // otherwise recreate it from the default branch.
      const { data } = await request("POST", apiUrlFor("/releases"), {
        expect: 201,
        json: {
          tag_name: tag,
          target_commitish: sha,
          name,
          body: notes,
          draft: true,
          prerelease: true,
          make_latest: "false",
        },
      });
      return data;
    },
    async getRelease(id) {
      return (await request("GET", apiUrlFor(`/releases/${id}`), { expect: 200 })).data;
    },
    async listAssets(id) {
      const url = apiUrlFor(`/releases/${id}/assets`);
      url.searchParams.set("per_page", "100");
      return paginate(url);
    },
    async uploadAsset(id, assetName, bytes) {
      const url = new URL(`${uploadBase.pathname.replace(/\/+$/, "")}${repoPath}/releases/${id}/assets`, uploadBase.origin);
      url.searchParams.set("name", assetName);
      return (await request("POST", url, { expect: 201, bytes })).data;
    },
    async publish(id) {
      return (
        await request("PATCH", apiUrlFor(`/releases/${id}`), {
          expect: 200,
          json: { draft: false, prerelease: true, make_latest: "false" },
        })
      ).data;
    },
    async deleteRelease(id) {
      await request("DELETE", apiUrlFor(`/releases/${id}`), { expect: 204 });
    },
  };
}

function assetSignature(asset) {
  return `${asset.name} state=${asset.state} size=${asset.size} digest=${asset.digest ?? "none"}`;
}

function assertReleaseFields(release, { id, tag, draft }) {
  if (!release || release.id !== id || release.tag_name !== tag || release.draft !== draft || release.prerelease !== true) {
    fail(
      `Release ${id} is ${JSON.stringify({
        id: release?.id,
        tag_name: release?.tag_name,
        draft: release?.draft,
        prerelease: release?.prerelease,
      })}, expected tag ${tag}, draft=${draft}, prerelease=true`,
    );
  }
}

function assertExactAssets(id, actualAssets, expectedAssets) {
  const expected = expectedAssets
    .map((asset) => assetSignature({ name: asset.name, state: "uploaded", size: asset.size, digest: `sha256:${asset.digest}` }))
    .sort();
  const actual = actualAssets.map(assetSignature).sort();
  if (actual.join("\n") !== expected.join("\n")) {
    fail(`Release ${id} assets do not match the verified bundles.\nExpected:\n${expected.join("\n")}\nActual:\n${actual.join("\n")}`);
  }
}

async function assertTagCommit(client, tag, sha) {
  const chain = await client.tagCommitChain(tag);
  if (!chain.includes(sha)) {
    fail(`refs/tags/${tag} resolves to ${chain.join(" -> ")}, not the workflow commit ${sha}`);
  }
}

async function assertOnlyRelease(client, tag, id) {
  const ids = (await client.listReleasesForTag(tag)).map((release) => release.id);
  if (ids.length !== 1 || ids[0] !== id) {
    fail(`Expected release ${id} to be the only release for ${tag}, found [${ids.join(", ")}]`);
  }
}

async function verifyRelease(client, { id, tag, draft, assets }) {
  assertReleaseFields(await client.getRelease(id), { id, tag, draft });
  assertExactAssets(id, await client.listAssets(id), assets);
  await assertOnlyRelease(client, tag, id);
}

export async function preflightRelease({ client, tag, sha }) {
  validateTag(tag);
  if (!COMMIT_PATTERN.test(sha ?? "")) {
    fail(`Workflow commit ${JSON.stringify(sha)} is not a full SHA`);
  }
  await assertTagCommit(client, tag, sha);
  const published = await client.releaseForTag(tag);
  if (published) {
    fail(`Release ${published.id} already exists for ${tag}. Delete it and its assets before re-running.`);
  }
  const existing = await client.listReleasesForTag(tag);
  if (existing.length > 0) {
    fail(
      `A release already exists for ${tag}: ${existing
        .map((release) => `id=${release.id} draft=${release.draft}`)
        .join(", ")}. Delete it and its assets before re-running.`,
    );
  }
}

export async function publishRelease({ client, tag, sha, name, notes, assets, log = () => {} }) {
  await preflightRelease({ client, tag, sha });

  const created = await client.createDraft({ tag, sha, name, notes });
  const id = created?.id;
  if (!Number.isSafeInteger(id) || id <= 0) {
    fail("Release creation did not return a release ID");
  }
  log(`Created draft release ${id} for ${tag}`);

  try {
    assertReleaseFields(created, { id, tag, draft: true });
    for (const asset of assets) {
      const bytes = readFileSync(asset.path);
      if (bytes.length !== asset.size || sha256(bytes) !== asset.digest) {
        fail(`${asset.name} changed on disk after it was verified`);
      }
      const uploaded = await client.uploadAsset(id, asset.name, bytes);
      if (uploaded?.name !== asset.name || uploaded?.state !== "uploaded" || uploaded?.size !== asset.size) {
        fail(`Upload of ${asset.name} to release ${id} came back as ${JSON.stringify(uploaded?.name)} (${uploaded?.state})`);
      }
      if (uploaded.digest && uploaded.digest !== `sha256:${asset.digest}`) {
        fail(`GitHub recorded ${uploaded.digest} for ${asset.name}, expected sha256:${asset.digest}`);
      }
      log(`Uploaded ${asset.name}`);
    }
    await verifyRelease(client, { id, tag, draft: true, assets });
    await assertTagCommit(client, tag, sha);
  } catch (error) {
    await discardDraft(client, id, log);
    throw error;
  }

  let published;
  try {
    published = await client.publish(id);
    if (published?.id !== id || published?.draft !== false) {
      fail(`Publishing release ${id} did not return it as published`);
    }
  } catch (error) {
    await discardDraft(client, id, log);
    throw error;
  }
  log(`Published release ${id}`);

  try {
    await verifyRelease(client, { id, tag, draft: false, assets });
    const byTag = await client.releaseForTag(tag);
    if (byTag?.id !== id) {
      fail(`The release for ${tag} is ${byTag?.id ?? "missing"}, not ${id}`);
    }
    await assertTagCommit(client, tag, sha);
  } catch (error) {
    fail(`Release ${id} was published but failed post-publish verification; review it by hand. ${error.message}`);
  }
  return { id, htmlUrl: published.html_url };
}

async function discardDraft(client, id, log) {
  try {
    const release = await client.getRelease(id);
    if (release?.draft === true) {
      await client.deleteRelease(id);
      log(`Deleted draft release ${id}`);
    } else {
      log(`Left release ${id} in place because it is no longer a draft`);
    }
  } catch (error) {
    log(`Could not delete draft release ${id}: ${error.message}`);
  }
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = {};
  for (let i = 0; i < rest.length; i += 2) {
    const key = rest[i];
    const value = rest[i + 1];
    if (!key?.startsWith("--") || value === undefined) {
      fail(`Unexpected arguments: ${rest.join(" ")}`);
    }
    options[key.slice(2)] = value;
  }
  return { command, options };
}

async function main(argv, env) {
  const { command, options } = parseArgs(argv);
  const tag = validateTag(options.tag);
  const client = createGitHubClient({ apiUrl: env.GITHUB_API_URL || undefined, token: env.GH_TOKEN, repo: options.repo });
  const log = (message) => console.log(message);

  if (command === "preflight") {
    await preflightRelease({ client, tag, sha: options.sha });
    log(`No release exists for ${tag}`);
    return;
  }
  if (command === "publish") {
    if (!options.name || !options["notes-file"] || !options["assets-dir"]) {
      fail("publish needs --name, --notes-file, and --assets-dir");
    }
    const assets = loadReleaseAssets(options["assets-dir"]);
    const notes = readFileSync(options["notes-file"], "utf8");
    const { id, htmlUrl } = await publishRelease({ client, tag, sha: options.sha, name: options.name, notes, assets, log });
    log(`Release ${id}: ${htmlUrl}`);
    return;
  }
  fail(`Unknown command ${JSON.stringify(command)}; use preflight or publish`);
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2), process.env).catch((error) => {
    console.error(`::error::${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  });
}
