/**
 * On a phone-width screen, marks the spec tables more than three viewport
 * heights from view so global CSS leaves out their cell labels, and gives a
 * table its labels back once it comes within that reach. Chrome renders a
 * content-visibility: auto table from about 1.5 viewport heights away, so a
 * table has its labels again before it renders. Scrolling checks before the
 * frame paints, so a jump to a far section shows its labels too.
 *
 * The page runs this from its source text, so it can only use what it declares.
 */
export function leaveOutFarLabels() {
  if (!matchMedia('screen and (max-width: 720px)').matches) return;
  // Measuring the table itself would lay out what content-visibility skips.
  const isFar = (table) => {
    const reach = 3 * innerHeight;
    const { top, bottom } = table.parentElement.getBoundingClientRect();
    return top > innerHeight + reach || bottom < -reach;
  };
  let far = [...document.querySelectorAll('.spec-reader .docs-table-scroll > table')].filter(isFar);
  if (!far.length) return;
  const restore = () => {
    far = far.filter((table) => {
      if (isFar(table)) return true;
      table.removeAttribute('data-labels');
      return false;
    });
    if (far.length) return;
    observer.disconnect();
    removeEventListener('scroll', restore);
  };
  // The spec resolves a percentage root margin against the viewport's width.
  const observer = new IntersectionObserver(restore, { rootMargin: `${3 * innerHeight}px 0px` });
  for (const table of far) {
    table.setAttribute('data-labels', 'lazy');
    observer.observe(table.parentElement);
  }
  addEventListener('scroll', restore, { passive: true });
}
