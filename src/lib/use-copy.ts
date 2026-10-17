'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { announce } from './announce';

/**
 * Copies text to the clipboard, announces `message`, and reports `copied`
 * for `resetMs` so the caller can swap its label or icon.
 */
export function useCopy(message: string, resetMs = 1500) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);

  useEffect(() => () => clearTimeout(timer.current), []);

  const copy = useCallback(
    async (text: string) => {
      try {
        await navigator.clipboard.writeText(text);
      } catch {
        return;
      }
      announce(message);
      setCopied(true);
      clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), resetMs);
    },
    [message, resetMs],
  );

  return { copied, copy };
}
