/**
 * Same-origin guard for server-supplied next links (rule 9, foreign-origin next link class).
 *
 * A paginated listing hands the client its next page as a URL: a `Link: <...>; rel="next"` header,
 * HAL `_links.next.href`, OData `@odata.nextLink`, JSON:API `links.next`, a `next_page` or
 * `nextPageUrl` field. A client that follows whatever the server names and attaches its credential
 * to the request sends that credential to any origin the response chooses (CodeRabbit on #62:
 * `servicenow.ts` followed `Link rel=next` to any host with the Authorization header attached). The
 * rule for every walk: a server-supplied next URL is resolved against the configured base and
 * followed only when it shares the base's origin (scheme, host, and port) and carries no userinfo;
 * otherwise the walk stops, the dataset is truncated, and the stop is described with fixed text
 * that names the configured origin and the rejected origin, never the link's path, query, fragment,
 * or userinfo, any of which may carry a token. `resolveSameOriginUrl` is the single implementation
 * the integrations use; `nextLinkStop` turns its error into the `describePagination` stop.
 */
import { IntegrationError } from "./error-text.js";
import type { PaginationStop } from "./pagination.js";

/** Why a next link was not followed. */
export type NextLinkRejection = "foreign_origin" | "userinfo" | "unparseable";

/** The `code` of every `NextLinkError`. */
export const NEXT_LINK_REJECTED_CODE = "NEXT_LINK_REJECTED";

/** The `code` of the error thrown when the configured base itself is not an absolute URL. */
export const INVALID_CONFIGURED_ORIGIN_CODE = "INVALID_CONFIGURED_ORIGIN";

/**
 * The origin of a URL as this module names it: scheme, host, and port (`https://api.example.com`,
 * `http://10.0.0.1:8080`), or the scheme alone when the URL has no host (`javascript:`, `data:`).
 */
export function originOf(url: URL): string {
  return url.host.length > 0 ? `${url.protocol}//${url.host}` : url.protocol;
}

/**
 * Thrown by `resolveSameOriginUrl`. The message is fixed text plus the configured origin and, for a
 * foreign origin, the rejected origin; `rejectedOrigin` is undefined for the other reasons. Neither
 * field nor the message ever holds the link's path, query, fragment, or userinfo.
 */
export class NextLinkError extends IntegrationError {
  readonly reason: NextLinkRejection;
  readonly configuredOrigin: string;
  readonly rejectedOrigin: string | undefined;

  constructor(reason: NextLinkRejection, configuredOrigin: string, rejectedOrigin?: string) {
    super(nextLinkMessage(reason, configuredOrigin, rejectedOrigin), { code: NEXT_LINK_REJECTED_CODE });
    this.reason = reason;
    this.configuredOrigin = configuredOrigin;
    this.rejectedOrigin = rejectedOrigin;
  }
}

function nextLinkMessage(reason: NextLinkRejection, configuredOrigin: string, rejectedOrigin: string | undefined): string {
  switch (reason) {
    case "foreign_origin":
      return `next link to ${rejectedOrigin ?? "another origin"} was not followed because it does not share the configured origin ${configuredOrigin}`;
    case "userinfo":
      return `next link was not followed because it carries userinfo (configured origin ${configuredOrigin})`;
    case "unparseable":
      return `next link was not followed because it could not be parsed against the configured origin ${configuredOrigin}`;
    default: {
      const unhandled: never = reason;
      throw new Error(`Unhandled next link rejection ${String(unhandled)}`);
    }
  }
}

function parseBase(base: string | URL): URL {
  if (base instanceof URL) return base;
  try {
    return new URL(base);
  } catch {
    // The base is the integration's own configuration, not server text, but a config value can hold a token too, so it is never echoed.
    throw new IntegrationError("configured origin could not be parsed as an absolute URL", { code: INVALID_CONFIGURED_ORIGIN_CODE });
  }
}

/**
 * Resolves a server-supplied next link against the configured base and returns it only when it may
 * be followed with the base's credential: a relative link (`/api/v2/users?page=3`, `?cursor=abc`,
 * `next?page=2`) resolves onto the base; an absolute link passes only when its scheme, host, and
 * port equal the base's. A link naming another host, scheme, or port, a protocol-relative `//host`
 * link to another host, an IP literal that is not the configured host, a link carrying userinfo
 * (`https://user:secret@host/...`), and a link that does not parse (an empty string included) throw
 * `NextLinkError` with fixed text that names only the configured origin and, for a foreign origin,
 * the rejected origin. The returned URL is the one to request; the caller still sends it through the
 * scrub before recording it anywhere, since its query may carry a token.
 */
export function resolveSameOriginUrl(candidate: string, base: string | URL): URL {
  const baseUrl = parseBase(base);
  const configuredOrigin = originOf(baseUrl);
  if (typeof candidate !== "string" || candidate.trim().length === 0) throw new NextLinkError("unparseable", configuredOrigin);
  let url: URL;
  try {
    url = new URL(candidate, baseUrl);
  } catch {
    throw new NextLinkError("unparseable", configuredOrigin);
  }
  if (url.protocol !== baseUrl.protocol || url.host !== baseUrl.host) throw new NextLinkError("foreign_origin", configuredOrigin, originOf(url));
  if (url.username.length > 0 || url.password.length > 0) throw new NextLinkError("userinfo", configuredOrigin);
  return url;
}

/** The `describePagination` stop for a rejected next link: the reason, and the rejected origin when the link named a foreign one. */
export function nextLinkStop(error: NextLinkError): PaginationStop {
  return error.rejectedOrigin === undefined
    ? { kind: "rejected_next_link", reason: error.reason }
    : { kind: "rejected_next_link", reason: error.reason, origin: error.rejectedOrigin };
}
