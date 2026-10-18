'use client';

import Link from 'next/link';
import { useRef, type SyntheticEvent } from 'react';
import { getDocHref, type DocsSection, type DocsSectionItem } from '../lib/docs';

function DocsNavLink({ item, currentSlug }: { item: DocsSectionItem; currentSlug: string }) {
  const active = item.slug === currentSlug;
  return (
    <Link
      href={getDocHref(item.slug)}
      className={active ? 'docs-sidebar-link is-active' : 'docs-sidebar-link'}
      aria-current={active ? 'page' : undefined}
    >
      {item.label}
    </Link>
  );
}

export function DocsMobileNav({
  sections,
  currentSlug,
}: {
  sections: DocsSection[];
  currentSlug: string;
}) {
  const navRef = useRef<HTMLElement>(null);

  function scrollToActive(event: SyntheticEvent<HTMLDetailsElement>) {
    const nav = navRef.current;
    const active = nav?.querySelector<HTMLElement>('.is-active');
    if (event.currentTarget.open && nav && active) {
      nav.scrollTop = active.offsetTop - nav.clientHeight / 2;
    }
  }

  return (
    <details className="docs-mobile-nav lg:hidden" onToggle={scrollToActive}>
      <summary>Browse docs</summary>
      <nav className="docs-sidebar-nav" aria-label="Docs navigation" ref={navRef}>
        {sections.map((section) => (
          <div key={section.title} className="docs-sidebar-section">
            <div className="docs-sidebar-title">{section.title}</div>
            {section.items.map((item) => {
              const open =
                item.slug === currentSlug || item.items?.some((child) => child.slug === currentSlug);
              return (
                <div key={item.slug}>
                  <DocsNavLink item={item} currentSlug={currentSlug} />
                  {open && item.items ? (
                    <div className="docs-sidebar-children">
                      {item.items.map((child) => (
                        <DocsNavLink key={child.slug} item={child} currentSlug={currentSlug} />
                      ))}
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>
        ))}
      </nav>
    </details>
  );
}
