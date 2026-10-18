'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect, useId, useRef, useState, type FocusEvent, type MouseEvent, type RefObject } from 'react';
import type * as PageTree from 'fumadocs-core/page-tree';
import { useItems, useTOCItems } from 'fumadocs-ui/components/toc';
import { useTreeContext, useTreePath } from 'fumadocs-ui/contexts/tree';
import { TOCPopover, type TOCPopoverProps } from 'fumadocs-ui/layouts/docs/page/slots/toc';
import { CloseIcon, MenuIcon } from './icons';

function DocsMenuLink({ item, path }: { item: PageTree.Item; path: PageTree.Node[] }) {
  const active = item === path.at(-1);
  return (
    <Link
      href={item.url}
      className={active ? 'docs-sidebar-link is-active' : 'docs-sidebar-link'}
      aria-current={active ? 'page' : undefined}
    >
      {item.name}
    </Link>
  );
}

function DocsMenuNode({ node, path }: { node: PageTree.Node; path: PageTree.Node[] }) {
  switch (node.type) {
    case 'separator':
      return <div className="docs-sidebar-title">{node.name}</div>;
    case 'page':
      return <DocsMenuLink item={node} path={path} />;
    case 'folder': {
      // A folder without an index page has no link that opens it, so its pages always show.
      const open = !node.index || path.includes(node);
      return (
        <div>
          {node.index ? (
            <DocsMenuLink item={node.index} path={path} />
          ) : (
            <div className="docs-sidebar-folder">{node.name}</div>
          )}
          {open ? (
            <div className="docs-sidebar-children">
              {node.children.map((child, i) => (
                <DocsMenuNode key={i} node={child} path={path} />
              ))}
            </div>
          ) : null}
        </div>
      );
    }
    default: {
      const unhandled: never = node;
      return unhandled;
    }
  }
}

function DocsMenu() {
  const { root } = useTreeContext();
  const path = useTreePath();
  const pathname = usePathname();
  // Opening remembers the page, so the menu is closed again after any navigation.
  const [openOn, setOpenOn] = useState<string | null>(null);
  const open = openOn === pathname;
  const menuRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const panel = panelRef.current;
    if (!open || !panel) return;
    const current = panel.querySelector<HTMLElement>('[aria-current="page"]') ?? panel.querySelector('a');
    if (current) {
      panel.scrollTop = current.offsetTop - panel.clientHeight / 2;
      current.focus({ preventScroll: true });
    }

    // Pointer events, unlike clicks, reach the document from any tap on iOS Safari.
    function onPointerDown(event: PointerEvent) {
      if (!menuRef.current?.contains(event.target as Node)) setOpenOn(null);
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key !== 'Escape') return;
      setOpenOn(null);
      buttonRef.current?.focus();
    }
    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  function closeOnLink(event: MouseEvent<HTMLDivElement>) {
    if ((event.target as Element).closest('a')) setOpenOn(null);
  }

  // A tap on plain text in the panel blurs with no relatedTarget; only focus moving
  // to another element, such as tabbing past the last link, closes the menu.
  function closeOnFocusLeaving(event: FocusEvent<HTMLDivElement>) {
    if (event.relatedTarget && !event.currentTarget.contains(event.relatedTarget)) setOpenOn(null);
  }

  return (
    <div ref={menuRef} className="docs-menu lg:hidden" onBlur={closeOnFocusLeaving}>
      <button
        ref={buttonRef}
        type="button"
        className="docs-menu-button"
        aria-expanded={open}
        aria-controls="docs-menu-panel"
        onClick={() => setOpenOn(open ? null : pathname)}
      >
        {open ? <CloseIcon /> : <MenuIcon />}
        Docs
      </button>
      <div ref={panelRef} id="docs-menu-panel" className="docs-menu-panel" hidden={!open} onClick={closeOnLink}>
        <nav className="docs-sidebar-nav" aria-label="Docs navigation">
          {root.children.map((node, i) => (
            <DocsMenuNode key={i} node={node} path={path} />
          ))}
        </nav>
      </div>
    </div>
  );
}

/**
 * Names the contents trigger after the text it shows: the active heading, or
 * the page title while the list is open. The button's own content would read
 * as the reading-progress value, then the page title and the heading run
 * together, since Fumadocs keeps both in it and fades one out. The name stays
 * rendered, out of sight and out of the accessibility tree, because Chrome
 * spaces out a `hidden` element's text ("KSI-PIY-GIV : Generating").
 */
function ContentsTriggerName({ id, trigger }: { id: string; trigger: RefObject<HTMLButtonElement | null> }) {
  // Fumadocs keeps the popover's open state to itself, so follow the button's.
  const [open, setOpen] = useState(false);
  useEffect(() => {
    const button = trigger.current;
    if (!button) return;
    const observer = new MutationObserver(() => setOpen(button.getAttribute('aria-expanded') === 'true'));
    observer.observe(button, { attributes: true, attributeFilter: ['aria-expanded'] });
    return () => observer.disconnect();
  }, [trigger]);

  const page = useTreePath().at(-1)?.name;
  const heading = useItems().find((item) => item.active)?.original.title;
  const shown = (open ? undefined : heading) ?? page;
  return (
    <span id={id} className="sr-only" aria-hidden="true">
      On this page{shown ? <>: {shown}</> : null}
    </span>
  );
}

const barClassName = 'docs-contents-bar sticky top-(--fd-docs-row-2) z-10 grid [grid-area:toc-popover] h-(--fd-toc-popover-height)';

/**
 * Fumadocs' table-of-contents bar with a docs menu at its start, so every docs
 * page stays one tap away below 1024px, where the sidebar is hidden.
 */
export function DocsContentsBar(props: TOCPopoverProps) {
  const hasToc = useTOCItems().length > 0;
  const triggerRef = useRef<HTMLButtonElement>(null);
  const triggerNameId = useId();
  // Without headings the bar holds only the menu, which the sidebar replaces from 1024px.
  const shownBelow = hasToc
    ? 'xl:hidden max-xl:layout:[--fd-toc-popover-height:--spacing(10)]'
    : 'lg:hidden max-lg:layout:[--fd-toc-popover-height:--spacing(10)]';
  return (
    <div className={`${barClassName} ${shownBelow}`}>
      <DocsMenu />
      {hasToc ? (
        <>
          <TOCPopover
            {...props}
            trigger={{ ...props.trigger, ref: triggerRef, 'aria-labelledby': triggerNameId }}
            container={{ className: 'static z-auto' }}
          />
          <ContentsTriggerName id={triggerNameId} trigger={triggerRef} />
        </>
      ) : (
        <div className="docs-contents-bar-fill" />
      )}
    </div>
  );
}
