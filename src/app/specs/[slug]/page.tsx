import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { pageMetadata } from '../../../lib/metadata';
import { getSpec, loadSpecs } from '../../../lib/specs';

interface PageProps {
  params: Promise<{ slug: string }>;
}

async function getSpecOrNotFound(props: PageProps) {
  const { slug } = await props.params;
  const spec = getSpec(slug);
  if (!spec) notFound();
  return spec;
}

export function generateStaticParams() {
  return loadSpecs().map((spec) => ({ slug: spec.slug }));
}

export async function generateMetadata(props: PageProps): Promise<Metadata> {
  const { meta } = await getSpecOrNotFound(props);
  return pageMetadata({
    title: `${meta.name}: grclanker`,
    description: `Compliance automation spec for ${meta.vendor}. ${meta.name}.`,
    path: `/specs/${meta.slug}/`,
  });
}

export default async function SpecPage(props: PageProps) {
  const { meta, content } = await getSpecOrNotFound(props);
  return (
    <section className="mx-auto max-w-content px-4 py-6 sm:px-6 sm:py-8">
      <h1 className="text-lg font-bold text-text">{meta.name}</h1>
      <pre className="mt-6">{content}</pre>
    </section>
  );
}
