import type { ReactNode } from 'react';
import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import { NoNavTitle } from '../../components/docs-slots';
import { getDocsTree } from '../../lib/source';

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <DocsLayout
      tree={getDocsTree()}
      nav={{ enabled: false }}
      searchToggle={{ enabled: false }}
      themeSwitch={{ enabled: false }}
      sidebar={{ collapsible: false, prefetch: false, 'aria-label': 'Docs navigation' }}
      tabs={false}
      slots={{ navTitle: NoNavTitle }}
    >
      {children}
    </DocsLayout>
  );
}
