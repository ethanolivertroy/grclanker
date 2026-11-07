/** The one clock, set of thresholds, and collection windows used by a Tenable run. */
export interface TenableAssessmentOptions {
  now?: number;
  staleScanDays?: number;
  staleAssetDays?: number;
  agentOfflineDays?: number;
  pluginStaleHours?: number;
  inactiveUserDays?: number;
  maxAdmins?: number;
  credentialThreshold?: number;
  taggedThreshold?: number;
  auditLookbackDays?: number;
  vulnLookbackDays?: number;
  slaCriticalDays?: number;
  slaHighDays?: number;
  slaMediumDays?: number;
  slaLowDays?: number;
  expectedAssetCount?: number;
  maxChunks?: number;
}

export const TENABLE_ASSESSMENT_DEFAULTS = {
  maxChunks: 50,
  staleScanDays: 30,
  staleAssetDays: 30,
  agentOfflineDays: 7,
  pluginStaleHours: 24,
  inactiveUserDays: 90,
  maxAdmins: 5,
  credentialThreshold: 0.8,
  taggedThreshold: 0.9,
  auditLookbackDays: 30,
  vulnLookbackDays: 90,
  slaCriticalDays: 15,
  slaHighDays: 30,
  slaMediumDays: 90,
  slaLowDays: 180,
} as const;

export interface TenableRunPlan extends Required<Omit<TenableAssessmentOptions, "expectedAssetCount">> {
  expectedAssetCount?: number;
  scanResultsSinceUnix: number;
  auditSinceIso: string;
  vulnerabilitiesSinceUnix: number;
}

function bounded(value: number | undefined, fallback: number, min: number, max: number): number {
  return Math.min(Math.max(value === undefined || !Number.isFinite(value) ? fallback : value, min), max);
}

function integer(value: number | undefined, fallback: number, min: number, max: number): number {
  return Math.trunc(bounded(value, fallback, min, max));
}

export function resolveTenableRunPlan(options: TenableAssessmentOptions = {}): TenableRunPlan {
  const defaults = TENABLE_ASSESSMENT_DEFAULTS;
  const now = options.now ?? Date.now();
  const staleScanDays = integer(options.staleScanDays, defaults.staleScanDays, 1, 365);
  const auditLookbackDays = integer(options.auditLookbackDays, defaults.auditLookbackDays, 1, 365);
  const vulnLookbackDays = integer(options.vulnLookbackDays, defaults.vulnLookbackDays, 1, 730);
  const dayMs = 86_400_000;
  return {
    now,
    staleScanDays,
    auditLookbackDays,
    vulnLookbackDays,
    staleAssetDays: integer(options.staleAssetDays, defaults.staleAssetDays, 1, 365),
    agentOfflineDays: integer(options.agentOfflineDays, defaults.agentOfflineDays, 1, 365),
    pluginStaleHours: integer(options.pluginStaleHours, defaults.pluginStaleHours, 1, 24 * 30),
    inactiveUserDays: integer(options.inactiveUserDays, defaults.inactiveUserDays, 1, 3650),
    maxAdmins: integer(options.maxAdmins, defaults.maxAdmins, 0, 10000),
    credentialThreshold: bounded(options.credentialThreshold, defaults.credentialThreshold, 0, 1),
    taggedThreshold: bounded(options.taggedThreshold, defaults.taggedThreshold, 0, 1),
    slaCriticalDays: integer(options.slaCriticalDays, defaults.slaCriticalDays, 1, 3650),
    slaHighDays: integer(options.slaHighDays, defaults.slaHighDays, 1, 3650),
    slaMediumDays: integer(options.slaMediumDays, defaults.slaMediumDays, 1, 3650),
    slaLowDays: integer(options.slaLowDays, defaults.slaLowDays, 1, 3650),
    expectedAssetCount: options.expectedAssetCount,
    maxChunks: integer(options.maxChunks, defaults.maxChunks, 1, 1000),
    scanResultsSinceUnix: Math.floor((now - staleScanDays * dayMs) / 1000),
    auditSinceIso: new Date(now - auditLookbackDays * dayMs).toISOString(),
    vulnerabilitiesSinceUnix: Math.floor((now - vulnLookbackDays * dayMs) / 1000),
  };
}
