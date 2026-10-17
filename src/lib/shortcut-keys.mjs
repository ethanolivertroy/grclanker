function hasModifier(event) {
  return event.metaKey || event.ctrlKey || event.altKey;
}

function isTypingTarget(target) {
  return /^(input|textarea|select)$/i.test(target?.tagName ?? '') || target?.isContentEditable === true;
}

function matchesHotKey(event, hotKey) {
  return hotKey.every(({ key }) => (typeof key === 'string' ? event.key === key : key(event)));
}

/**
 * Keydown handler for the site-wide `/`, `?`, `c`, and `h` shortcuts. The search
 * provider owns its Cmd/Ctrl+K hotkey everywhere except over the help dialog.
 *
 * @param {{
 *   help: HTMLDialogElement | null,
 *   searchOpen: boolean,
 *   searchHotKey: { key: string | ((event: KeyboardEvent) => boolean) }[],
 *   openSearch: () => void,
 *   copyRawUrl: () => void,
 *   goHome: () => void,
 * }} options
 * @returns {(event: KeyboardEvent) => void}
 */
export function shortcutHandler({ help, searchOpen, searchHotKey, openSearch, copyRawUrl, goHome }) {
  return (event) => {
    if (event.defaultPrevented || searchOpen) return;
    if (help?.open) {
      if (matchesHotKey(event, searchHotKey)) {
        // Search would open under the modal help dialog, which stays in the
        // top layer and leaves the page inert. preventDefault() keeps the
        // provider's own hotkey handler from toggling search back closed.
        event.preventDefault();
        help.close();
        openSearch();
      } else if (event.key === '?' && !hasModifier(event)) {
        event.preventDefault();
        help.close();
      }
      return;
    }
    if (hasModifier(event) || isTypingTarget(event.target)) return;
    if (event.key === '/') {
      event.preventDefault();
      openSearch();
    } else if (event.key === '?') {
      event.preventDefault();
      help?.showModal();
    } else if (event.key === 'c') {
      copyRawUrl();
    } else if (event.key === 'h') {
      goHome();
    }
  };
}
