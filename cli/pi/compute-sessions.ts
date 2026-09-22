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

export async function teardownComputeSessions(): Promise<void> {
  const handles = [...activeSessions];
  activeSessions.clear();
  for (const handle of handles) {
    try {
      await handle.teardown();
    } catch {
      // best effort: a failed teardown must not mask the caller's result
    }
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
