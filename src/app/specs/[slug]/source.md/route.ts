import { getSpec, loadSpecs } from '../../../../lib/specs';

export const revalidate = false;
export const dynamicParams = false;

export function generateStaticParams() {
  return loadSpecs().map((spec) => ({ slug: spec.slug }));
}

export async function GET(_request: Request, { params }: { params: Promise<{ slug: string }> }) {
  const spec = getSpec((await params).slug);
  if (!spec) return new Response('Not found', { status: 404 });
  return new Response(spec.content.trim(), { headers: { 'Content-Type': 'text/markdown; charset=utf-8' } });
}
