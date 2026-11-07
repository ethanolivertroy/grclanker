/** Canonical word boundaries used by credential carriers and object-field policy. */
export const NON_CREDENTIAL_KEY_QUALIFIERS = new Set(["public"]);

export function propertyNameSegments(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((segment) => segment.length > 0);
}
