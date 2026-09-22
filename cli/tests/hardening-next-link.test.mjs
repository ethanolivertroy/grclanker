import test from "node:test";
import assert from "node:assert/strict";

import { IntegrationError, REDACTED, errorMessage, scrubDataText, scrubError, scrubErrorText } from "../dist/extensions/grc-tools/hardening/error-text.js";
import { describePagination } from "../dist/extensions/grc-tools/hardening/pagination.js";
import {
  INVALID_CONFIGURED_ORIGIN_CODE,
  NEXT_LINK_REJECTED_CODE,
  NextLinkError,
  nextLinkStop,
  originOf,
  resolveSameOriginUrl,
} from "../dist/extensions/grc-tools/hardening/next-link.js";
import * as hardening from "../dist/extensions/grc-tools/hardening/index.js";
import { assertNoCanaryWindowIn, assertNoFragments, fragmentsOf } from "./helpers/hardening-canaries.mjs";

/**
 * Values planted in the parts of a rejected link that may carry a token: its path, query, fragment,
 * and userinfo. Random alphanumerics, distinct in every 8-character window, sharing no 6-character
 * window with the origins or the fixed text (asserted below), so a leak of any part is caught.
 */
const LINK_CANARY = Object.freeze({
  path: "Rm4vXq9ZtK2pWd7L",
  query: "Hf8sNc3JyB6gTe5Q",
  fragment: "Vp2kLz7XrD4mQw9S",
  user: "Ub5nGx8TqE3vHy6K",
  password: "Wj9cPf2RmA7tKs4D",
  base: "Yd6hBn3VwF8rJp5M",
});
const CANARIES = Object.freeze(Object.values(LINK_CANARY));

const BASE = "https://api.example.com/api/v2/users?per_page=100";
const CONFIGURED_ORIGIN = "https://api.example.com";

/** The tail every rejected absolute link carries: a token-bearing path, query, and fragment. */
const TAIL = `/collect/${LINK_CANARY.path}?token=${LINK_CANARY.query}&page=2#${LINK_CANARY.fragment}`;
const USERINFO = `${LINK_CANARY.user}:${LINK_CANARY.password}`;

/** Text a rendering is allowed to carry. */
const LEGITIMATE = Object.freeze([
  BASE,
  CONFIGURED_ORIGIN,
  "https://evil.example",
  "http://api.example.com",
  "https://api.example.com:8443",
  "http://10.0.0.1",
  "https://[::1]:8443",
  "https://api.example.com.",
  "javascript:",
  "data:",
  "next link to",
  "was not followed because it does not share the configured origin",
  "was not followed because it carries userinfo (configured origin",
  "was not followed because it could not be parsed against the configured origin",
  "configured origin could not be parsed as an absolute URL",
  "configured origin must be an http or https URL",
  "rather than the configured origin and was not followed",
  "carried userinfo and was not followed",
  "could not be parsed and was not followed",
]);

/** Every rendering of a thrown error an integration might record. */
function renderings(error) {
  const scrubbed = scrubError(error);
  return {
    message: error.message,
    folded: errorMessage(error),
    string: String(error),
    scrubbedMessage: scrubbed.message,
    scrubbedJson: JSON.stringify(scrubbed),
    ownJson: JSON.stringify(error),
  };
}

function assertRejected(candidate, reason, rejectedOrigin, label = candidate) {
  let thrown;
  try {
    resolveSameOriginUrl(candidate, BASE);
  } catch (error) {
    thrown = error;
  }
  assert.ok(thrown instanceof NextLinkError, `${label}: expected NextLinkError, got ${thrown && thrown.constructor.name}`);
  assert.ok(thrown instanceof IntegrationError, `${label}: NextLinkError extends IntegrationError`);
  assert.equal(thrown.code, NEXT_LINK_REJECTED_CODE, `${label}: code`);
  assert.equal(thrown.reason, reason, `${label}: reason`);
  assert.equal(thrown.configuredOrigin, CONFIGURED_ORIGIN, `${label}: configured origin`);
  assert.equal(thrown.rejectedOrigin, rejectedOrigin, `${label}: rejected origin`);
  assert.ok(thrown.message.includes(CONFIGURED_ORIGIN), `${label}: the message names the configured origin: ${thrown.message}`);
  if (rejectedOrigin !== undefined) assert.ok(thrown.message.includes(rejectedOrigin), `${label}: the message names the rejected origin: ${thrown.message}`);
  for (const [name, text] of Object.entries(renderings(thrown))) {
    assertNoFragments(text, CANARIES, { label: `${label} ${name}` });
    assert.ok(!text.includes("?token="), `${label} ${name}: the link's query leaked: ${text}`);
    assert.ok(!text.includes("@"), `${label} ${name}: userinfo leaked: ${text}`);
  }
  assert.equal(scrubErrorText(thrown.message), thrown.message, `${label}: the fixed text survives scrubErrorText`);
  assert.equal(scrubDataText(thrown.message), thrown.message, `${label}: the fixed text survives scrubDataText`);
  assert.ok(!thrown.message.includes(REDACTED), `${label}: the fixed text needs no marker`);
  return thrown;
}

test("fixture: no 6-character window of a planted value occurs in an origin or a fixed text", () => {
  assertNoCanaryWindowIn(LEGITIMATE, CANARIES);
  const windows = CANARIES.flatMap((value) => fragmentsOf(value, { minLength: 8, maxLength: 8 }));
  assert.equal(new Set(windows).size, windows.length, "two planted values share an 8-character window");
});

test("a relative next link resolves onto the configured base", () => {
  const cases = [
    ["/api/v2/users?page=3&cursor=abc", "https://api.example.com/api/v2/users?page=3&cursor=abc"],
    ["?cursor=abc", "https://api.example.com/api/v2/users?cursor=abc"],
    ["?page=2", "https://api.example.com/api/v2/users?page=2"],
    ["next?page=2", "https://api.example.com/api/v2/next?page=2"],
    ["../v3/users", "https://api.example.com/api/v3/users"],
    ["users?page=2#top", "https://api.example.com/api/v2/users?page=2#top"],
  ];
  for (const [candidate, href] of cases) {
    const url = resolveSameOriginUrl(candidate, BASE);
    assert.ok(url instanceof URL, `${candidate}: returns a URL`);
    assert.equal(url.href, href, candidate);
    assert.equal(originOf(url), CONFIGURED_ORIGIN, candidate);
  }
  assert.equal(resolveSameOriginUrl("/x", new URL("https://api.example.com/v1/")).href, "https://api.example.com/x", "the base may be a URL instance");
});

test("a same-origin absolute next link passes, whatever the case of its scheme and host or the form of its default port", () => {
  const cases = [
    ["https://api.example.com/api/v2/users?page=3", "https://api.example.com/api/v2/users?page=3"],
    ["HTTPS://API.EXAMPLE.COM/api/v2/users?page=3", "https://api.example.com/api/v2/users?page=3"],
    ["https://api.example.com:443/api/v2/users?page=3", "https://api.example.com/api/v2/users?page=3"],
    ["//api.example.com/api/v2/users?page=3", "https://api.example.com/api/v2/users?page=3"],
  ];
  for (const [candidate, href] of cases) assert.equal(resolveSameOriginUrl(candidate, BASE).href, href, candidate);
  assert.equal(resolveSameOriginUrl("http://10.0.0.1:8080/next?page=2", "http://10.0.0.1:8080/v1/").href, "http://10.0.0.1:8080/next?page=2", "a configured IP literal accepts links to the same IP and port");
  assert.equal(resolveSameOriginUrl("https://api.example.com:8443/next", "https://api.example.com:8443/v1/").href, "https://api.example.com:8443/next", "a configured port accepts links to the same port");
});

test("the returned URL keeps its query for the request, and the scrub removes a token from it before it is recorded", () => {
  const url = resolveSameOriginUrl(`/api/v2/users?page=3&token=${LINK_CANARY.query}`, BASE);
  assert.ok(url.href.includes(LINK_CANARY.query), "the request URL is returned as resolved");
  assertNoFragments(scrubErrorText(url.href), [LINK_CANARY.query], { label: "scrubbed request URL" });
  assertNoFragments(scrubDataText(url.href), [LINK_CANARY.query], { label: "data-scrubbed request URL" });
});

test("a next link to another host, scheme, or port, a protocol-relative link to another host, an IP literal, and a non-hierarchical scheme throw with fixed text naming only the two origins", () => {
  const cases = [
    [`https://evil.example${TAIL}`, "https://evil.example"],
    [`http://api.example.com${TAIL}`, "http://api.example.com"],
    [`https://api.example.com:8443${TAIL}`, "https://api.example.com:8443"],
    [`//evil.example${TAIL}`, "https://evil.example"],
    [`http://10.0.0.1${TAIL}`, "http://10.0.0.1"],
    [`https://[::1]:8443${TAIL}`, "https://[::1]:8443"],
    [`https://api.example.com.${TAIL}`, "https://api.example.com."],
    [`https://${USERINFO}@evil.example${TAIL}`, "https://evil.example"],
    [`javascript:alert('${LINK_CANARY.path}')`, "javascript:"],
    [`data:text/plain,${LINK_CANARY.path}`, "data:"],
  ];
  for (const [candidate, rejectedOrigin] of cases) {
    const error = assertRejected(candidate, "foreign_origin", rejectedOrigin);
    assert.equal(error.message, `next link to ${rejectedOrigin} was not followed because it does not share the configured origin ${CONFIGURED_ORIGIN}`, candidate);
  }
});

test("a same-origin next link carrying userinfo throws without echoing the userinfo, the path, or the query", () => {
  for (const candidate of [`https://${USERINFO}@api.example.com${TAIL}`, `https://${LINK_CANARY.user}@api.example.com${TAIL}`, `//${USERINFO}@api.example.com${TAIL}`]) {
    const error = assertRejected(candidate, "userinfo", undefined);
    assert.equal(error.message, `next link was not followed because it carries userinfo (configured origin ${CONFIGURED_ORIGIN})`, candidate);
  }
});

test("an empty, blank, malformed, or non-string next link throws as unparseable without echoing it", () => {
  for (const candidate of ["", "   ", "\n", `http://[bad/${LINK_CANARY.path}`, `https://exa mple.com/${LINK_CANARY.path}`, undefined, null, 42, { href: `https://evil.example${TAIL}` }]) {
    const error = assertRejected(candidate, "unparseable", undefined, JSON.stringify(candidate) ?? String(candidate));
    assert.equal(error.message, `next link was not followed because it could not be parsed against the configured origin ${CONFIGURED_ORIGIN}`);
  }
});

function assertInvalidBase(base, message, label = JSON.stringify(base) ?? String(base)) {
  for (const candidate of ["/api/v2/users?page=2", `https://api.example.com${TAIL}`, `blob:https://api.example.com/${LINK_CANARY.path}`]) {
    let thrown;
    try {
      resolveSameOriginUrl(candidate, base);
    } catch (error) {
      thrown = error;
    }
    assert.ok(thrown instanceof IntegrationError, `${label}: IntegrationError`);
    assert.ok(!(thrown instanceof NextLinkError), `${label}: a bad base is not a next-link rejection`);
    assert.equal(thrown.code, INVALID_CONFIGURED_ORIGIN_CODE, label);
    assert.equal(thrown.message, message, label);
    for (const [name, text] of Object.entries(renderings(thrown))) assertNoFragments(text, CANARIES, { label: `base ${label} ${name}` });
    assert.equal(scrubErrorText(thrown.message), thrown.message, `${label}: the fixed text survives scrubErrorText`);
    assert.equal(scrubDataText(thrown.message), thrown.message, `${label}: the fixed text survives scrubDataText`);
  }
}

test("a configured base that is not an absolute URL is rejected with fixed text that does not echo it", () => {
  for (const base of ["", "api.example.com", `/v1/${LINK_CANARY.base}`, `not a url ${LINK_CANARY.base}`]) {
    assertInvalidBase(base, "configured origin could not be parsed as an absolute URL");
  }
});

test("a configured base whose scheme is not http or https is rejected, as a string and as a URL, so hostless schemes cannot share an origin", () => {
  // CodeRabbit on #78: `blob:https://a/...` and `blob:https://b/...` have the same (empty) host, so
  // an origin comparison of scheme and host would pass a foreign embedded origin; only an http or
  // https base is a configured origin.
  const bases = [
    `blob:https://api.example.com/${LINK_CANARY.base}`,
    `blob:${LINK_CANARY.base}`,
    `javascript:alert('${LINK_CANARY.base}')`,
    `data:text/plain,${LINK_CANARY.base}`,
    `file:///etc/${LINK_CANARY.base}`,
    `ftp://api.example.com/${LINK_CANARY.base}`,
    `ws://api.example.com/${LINK_CANARY.base}`,
    `mailto:ops@api.example.com`,
    `HTTPX://api.example.com/`,
  ];
  for (const base of bases) {
    assertInvalidBase(base, "configured origin must be an http or https URL");
    assertInvalidBase(new URL(base), "configured origin must be an http or https URL", `URL(${JSON.stringify(base)})`);
  }
  // The http and https bases pass as strings and as URL instances, whatever the case of the scheme.
  for (const base of ["https://api.example.com/api/", "HTTPS://API.EXAMPLE.COM/api/", "http://api.example.com:8080/", new URL("https://api.example.com/api/")]) {
    assert.equal(resolveSameOriginUrl("/api/v2/users?page=2", base).pathname, "/api/v2/users", String(base));
  }
});

test("nextLinkStop turns the rejection into a truncated pagination stop whose note names only the rejected origin", () => {
  const foreign = assertRejected(`https://evil.example${TAIL}`, "foreign_origin", "https://evil.example");
  assert.deepEqual(nextLinkStop(foreign), { kind: "rejected_next_link", reason: "foreign_origin", origin: "https://evil.example" });
  const userinfo = assertRejected(`https://${USERINFO}@api.example.com${TAIL}`, "userinfo", undefined);
  assert.deepEqual(nextLinkStop(userinfo), { kind: "rejected_next_link", reason: "userinfo" });
  const unparseable = assertRejected(`http://[bad/${LINK_CANARY.path}`, "unparseable", undefined);
  assert.deepEqual(nextLinkStop(unparseable), { kind: "rejected_next_link", reason: "unparseable" });

  const expectations = [
    [foreign, "stopped after 40 of 120 items because the next link named https://evil.example rather than the configured origin and was not followed"],
    [userinfo, "stopped after 40 of 120 items because the next link carried userinfo and was not followed"],
    [unparseable, "stopped after 40 of 120 items because the next link could not be parsed and was not followed"],
  ];
  for (const [error, note] of expectations) {
    const outcome = describePagination(40, 120, nextLinkStop(error));
    assert.deepEqual(outcome, { complete: false, truncated: true, note }, error.reason);
    assertNoFragments(outcome.note, CANARIES, { label: `${error.reason} note` });
    assert.equal(scrubErrorText(outcome.note), outcome.note, `${error.reason}: the note survives the scrub`);
    assert.equal(scrubDataText(outcome.note), outcome.note, `${error.reason}: the note survives the data scrub`);
  }
  assert.equal(describePagination(0, null, nextLinkStop(foreign)).note, "stopped after 0 items because the next link named https://evil.example rather than the configured origin and was not followed");
});

test("the index re-exports the next-link helper additively", () => {
  assert.equal(hardening.resolveSameOriginUrl, resolveSameOriginUrl);
  assert.equal(hardening.NextLinkError, NextLinkError);
  assert.equal(hardening.nextLinkStop, nextLinkStop);
  assert.equal(hardening.originOf, originOf);
  assert.equal(hardening.NEXT_LINK_REJECTED_CODE, NEXT_LINK_REJECTED_CODE);
  assert.equal(hardening.INVALID_CONFIGURED_ORIGIN_CODE, INVALID_CONFIGURED_ORIGIN_CODE);
});
