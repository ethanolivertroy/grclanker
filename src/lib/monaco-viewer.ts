import loader from '@monaco-editor/loader';
import { catppuccinFrappe } from './monaco-theme';

interface MountMonacoViewerOptions {
  container: HTMLElement;
  source: string;
  signal: AbortSignal;
}

export interface MonacoViewerController {
  setOptions: (options: { wrap: boolean; map: boolean }) => void;
  layout: () => void;
  focus: () => void;
  dispose: () => void;
}

export async function mountMonacoViewer({
  container,
  source,
  signal,
}: MountMonacoViewerOptions): Promise<MonacoViewerController> {
  signal.throwIfAborted();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let abortLoad: (() => void) | undefined;
  const unavailable = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error('Editor loading timed out')), 8000);
    abortLoad = () => reject(signal.reason);
    signal.addEventListener('abort', abortLoad, { once: true });
  });
  const monaco = await Promise.race([loader.init(), unavailable]).finally(() => {
    clearTimeout(timer);
    if (abortLoad) signal.removeEventListener('abort', abortLoad);
  });
  signal.throwIfAborted();
  monaco.editor.defineTheme('catppuccin-frappe', catppuccinFrappe);

  const isMobile = window.innerWidth < 768;

  const editor = monaco.editor.create(container, {
    value: source,
    language: 'markdown',
    theme: 'catppuccin-frappe',
    readOnly: true,
    automaticLayout: true,
    wordWrap: 'on',
    lineNumbers: 'on',
    lineNumbersMinChars: isMobile ? 3 : 4,
    folding: !isMobile,
    smoothScrolling: true,
    fontSize: isMobile ? 12 : 13,
    lineHeight: isMobile ? 20 : 22,
    fontFamily: "'Berkeley Mono', ui-monospace, SFMono-Regular, Menlo, monospace",
    padding: { top: isMobile ? 12 : 16, bottom: isMobile ? 12 : 16 },
    minimap: { enabled: false },
    scrollBeyondLastLine: false,
    renderLineHighlight: isMobile ? 'none' : 'line',
    matchBrackets: 'always',
    guides: { indentation: !isMobile },
    overviewRulerLanes: 0,
    glyphMargin: false,
    lineDecorationsWidth: isMobile ? 12 : 18,
    scrollbar: {
      verticalScrollbarSize: isMobile ? 6 : 10,
      horizontalScrollbarSize: isMobile ? 6 : 10,
    },
    contextmenu: false,
    quickSuggestions: false,
    parameterHints: { enabled: false },
    hover: { enabled: false },
    codeLens: false,
    dragAndDrop: false,
    links: false,
    lightbulb: { enabled: false },
    suggest: { showWords: false },
    find: { addExtraSpaceOnTop: false },
  });

  function sizeContainer() {
    const mobile = window.innerWidth < 768;
    const lineCount = editor.getModel()?.getLineCount() ?? 1;
    const lineHeight = editor.getOption(monaco.editor.EditorOption.lineHeight);
    const contentHeight = lineCount * lineHeight + (mobile ? 24 : 32);
    const maxHeight = window.innerHeight * (mobile ? 0.7 : 0.85);
    const minHeight = mobile ? 300 : 400;
    const height = Math.max(minHeight, Math.min(contentHeight, maxHeight));
    container.style.height = `${height}px`;
    editor.layout();
  }

  sizeContainer();
  window.addEventListener('resize', sizeContainer);

  return {
    setOptions({ wrap, map }) {
      editor.updateOptions({ wordWrap: wrap ? 'on' : 'off', minimap: { enabled: map } });
      sizeContainer();
    },
    layout: sizeContainer,
    focus: () => editor.focus(),
    dispose() {
      window.removeEventListener('resize', sizeContainer);
      editor.dispose();
    },
  };
}
