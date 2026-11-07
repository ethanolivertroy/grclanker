export function formatProvenanceNote(provenance: {
  repo: string;
  path: string;
  branch: string;
  blobSha: string | null;
  version: string;
  upstreamLastUpdated: string;
  cacheStatus: string;
}) {
  return `Source: ${provenance.repo}/${provenance.path} @ ${provenance.branch}${provenance.blobSha ? ` (${provenance.blobSha.slice(0, 12)})` : ""} · Consolidated Rules ${provenance.version} · upstream ${provenance.upstreamLastUpdated} · ${provenance.cacheStatus}`;
}
