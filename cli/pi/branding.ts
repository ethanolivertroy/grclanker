import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

export const BRAND_NAME = "grclanker";
export const BRAND_CONFIG_DIR = ".grclanker";

type EmbeddedPiPackageJson = {
  piConfig?: {
    name?: string;
    configDir?: string;
  };
};

export function assertEmbeddedPiBranding(appRoot: string): void {
  const packageRoot = join(appRoot, "node_modules", "@mariozechner", "pi-coding-agent");
  const packageJsonPath = join(packageRoot, "package.json");

  if (!existsSync(packageJsonPath)) {
    throw new Error(`Embedded Pi package not found under ${packageRoot}`);
  }

  const pkg = JSON.parse(readFileSync(packageJsonPath, "utf8")) as EmbeddedPiPackageJson;
  if (
    pkg.piConfig?.name !== BRAND_NAME ||
    pkg.piConfig?.configDir !== BRAND_CONFIG_DIR
  ) {
    throw new Error(
      [
        "Embedded Pi package is not branded for grclanker isolation.",
        "Reinstall grclanker or use an official release bundle so the embedded Pi dependency is patched correctly.",
      ].join(" "),
    );
  }
}
