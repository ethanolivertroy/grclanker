import { leaveOutFarLabels } from '../lib/spec-table-labels.mjs';

/**
 * Runs leaveOutFarLabels once, as the HTML is parsed. Stacked on a phone,
 * every spec table cell shows its column header, and right after load Chrome
 * lays out every table, offscreen ones included, for a page content pass that
 * starts before hydration ends. Client-side navigations set this innerHTML,
 * where scripts never run, and keep every label.
 */
export function SpecTableLabels() {
  return <div hidden dangerouslySetInnerHTML={{ __html: `<script>(${leaveOutFarLabels.toString()})()</script>` }} />;
}
