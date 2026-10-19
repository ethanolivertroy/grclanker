import Link from 'next/link';
import { RAW_BASE, groupSpecsByCategory, type SpecMeta } from '../lib/specs';
import { SpecUrlCopyButton } from './spec-copy';

const headerClass = 'text-left pb-2 pr-4 hud-label !text-subtext1 !font-semibold';

export function SpecCatalogSection({ specs }: { specs: SpecMeta[] }) {
  const groups = Object.entries(groupSpecsByCategory(specs)).filter(([, group]) => group.specs.length > 0);

  return (
    <section className="viewscreen rounded-lg p-5 md:p-6 mb-8 scanlines relative">
      <div className="relative z-10">
        <div className="flex flex-col gap-2 mb-6 md:flex-row md:items-end md:justify-between">
          <div>
            <h2 className="font-semibold text-sm tracking-widest uppercase text-blue">Spec Catalog</h2>
            <p className="text-subtext0 text-sm mt-1 italic">
              Each integration ships with native grclanker tools and a repository spec. Copy the raw plan to inspect,
              extend, or reimplement it.
            </p>
          </div>
          <div className="text-[0.6875rem] font-mono uppercase tracking-[0.16em] text-subtext0">
            {specs.length} specs loaded
          </div>
        </div>

        {groups.map(([key, group]) => (
          <div key={key} className="mb-8 last:mb-0">
            <div className="spec-category-head">
              <img
                src={`/categories/${key === 'community-specs' ? 'devops-developer-platforms' : key}.webp`}
                alt=""
                className="spec-category-image"
                loading="lazy"
              />
              <div className="spec-category-overlay">
                <h3 className="spec-category-title">{group.label}</h3>
                <span className="spec-category-count">
                  {group.specs.length} {group.specs.length === 1 ? 'spec' : 'specs'}
                </span>
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr>
                    <th scope="col" className={headerClass}>
                      Spec
                    </th>
                    <th scope="col" className={`${headerClass} hidden sm:table-cell`}>
                      Vendor
                    </th>
                    <th scope="col" className={`${headerClass} hidden md:table-cell`}>
                      Updated
                    </th>
                    <th scope="col" className="spec-catalog-copy text-right pb-2 hud-label !text-subtext1 !font-semibold">
                      Raw URL
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {group.specs.map((spec) => (
                    <tr key={spec.slug} className="border-t border-surface0/40 transition-colors hover:bg-blue/[0.03]">
                      <td className="py-2.5 pr-4 align-top">
                        {/* Prefetching every row would download each spec's full markdown. */}
                        <Link
                          href={`/specs/${spec.slug}/`}
                          prefetch={false}
                          className="block font-semibold text-text hover:text-blue transition-colors leading-snug"
                        >
                          {spec.name}
                        </Link>
                        <span className="mt-1 block text-xs text-subtext0 sm:hidden">{spec.vendor}</span>
                      </td>
                      <td className="py-2.5 pr-4 align-top text-subtext1 hidden sm:table-cell">{spec.vendor}</td>
                      <td className="py-2.5 pr-4 align-top text-subtext0 text-[0.6875rem] font-mono uppercase tracking-[0.08em] hidden md:table-cell">
                        {spec.last_updated}
                      </td>
                      <td className="spec-catalog-copy py-2.5 text-right align-top">
                        <SpecUrlCopyButton
                          url={`${RAW_BASE}/${spec.slug}.spec.md`}
                          label="Copy"
                          detail={`raw URL for ${spec.name}`}
                          className="copy-btn spec-copy-btn"
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
