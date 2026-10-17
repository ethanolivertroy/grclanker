import Link from 'next/link';
import { pageMetadata } from '../../lib/metadata';
import { loadSpecs } from '../../lib/specs';

export const metadata = pageMetadata({
  title: 'Specs: grclanker',
  description:
    'Browse 35 repository specs for shipped grclanker integrations and compute backends, or reuse a raw spec with any agent.',
  path: '/specs/',
});

export default function SpecsPage() {
  return (
    <section className="mx-auto max-w-content px-4 py-16 sm:px-6">
      <h1 className="text-lg font-bold text-text">Specs</h1>
      <ul className="mt-6 space-y-2">
        {loadSpecs().map((spec) => (
          <li key={spec.slug}>
            <Link href={`/specs/${spec.slug}/`}>{spec.name}</Link>
          </li>
        ))}
      </ul>
    </section>
  );
}
