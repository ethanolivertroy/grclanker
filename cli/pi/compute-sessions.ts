export type ComputeSessionHandle = {
  teardown: () => Promise<void>;
  teardownSync?: () => void;
};

const activeSessions = new Set<ComputeSessionHandle>();
let exitHookInstalled = false;

function installExitHook(): void {
  if (exitHookInstalled) return;
  exitHookInstalled = true;
  process.once("exit", () => {
    teardownComputeSessionsSync();
  });
}

export function registerComputeSession(handle: ComputeSessionHandle): () => void {
  installExitHook();
  activeSessions.add(handle);
  return () => {
    activeSessions.delete(handle);
  };
}

export function activeComputeSessionCount(): number {
  return activeSessions.size;
}

// A session that fails to tear down stays tracked so a later sweep can retry it, and the failure
// is reported once every handle has had its turn.
export class ComputeSessionTeardownError extends Error {
  readonly failures: readonly string[];

  constructor(failures: readonly string[]) {
    super(
      `${failures.length} compute session${failures.length === 1 ? "" : "s"} could not be torn down and ${failures.length === 1 ? "stays" : "stay"} tracked:\n${failures.map((failure) => `- ${failure}`).join("\n")}`,
    );
    this.name = "ComputeSessionTeardownError";
    this.failures = failures;
  }
}

export async function teardownComputeSessions(): Promise<void> {
  const failures: string[] = [];
  for (const handle of [...activeSessions]) {
    try {
      await handle.teardown();
      activeSessions.delete(handle);
    } catch (error) {
      failures.push(error instanceof Error ? error.message : String(error));
    }
  }
  if (failures.length > 0) {
    throw new ComputeSessionTeardownError(failures);
  }
}

export function teardownComputeSessionsSync(): void {
  const handles = [...activeSessions];
  activeSessions.clear();
  for (const handle of handles) {
    try {
      handle.teardownSync?.();
    } catch {
      // best effort during process exit
    }
  }
}
