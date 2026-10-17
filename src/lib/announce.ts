let setTimer: ReturnType<typeof setTimeout> | undefined;
let clearTimer: ReturnType<typeof setTimeout> | undefined;

/** Speaks a status message through the polite live region in the root layout. */
export function announce(message: string) {
  const region = document.getElementById('site-announcer');
  if (!region) return;
  clearTimeout(setTimer);
  clearTimeout(clearTimer);
  // Empty first so repeating the same message is announced again.
  region.textContent = '';
  setTimer = setTimeout(() => {
    region.textContent = message;
    clearTimer = setTimeout(() => {
      region.textContent = '';
    }, 5000);
  }, 100);
}
