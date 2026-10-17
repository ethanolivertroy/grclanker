import { getDocHref } from './docs';
import { siteUrl } from './site';
import { getDocSlug, source } from './source';
import { loadSpecs } from './specs';

export function getSitemapPaths() {
  return [
    '/',
    '/about/',
    '/specs/',
    ...source.getPages().map((page) => getDocHref(getDocSlug(page))),
    ...loadSpecs().map((spec) => `/specs/${spec.slug}/`),
  ].sort();
}

export function xmlResponse(body: string) {
  return new Response(`<?xml version="1.0" encoding="UTF-8"?>${body}`, {
    headers: { 'Content-Type': 'application/xml' },
  });
}

export function absoluteUrl(path: string) {
  return new URL(path, siteUrl).href;
}
