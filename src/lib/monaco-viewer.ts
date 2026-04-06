import loader from '@monaco-editor/loader';
import { catppuccinFrappe } from './monaco-theme';

interface MountMonacoViewerOptions {
  container: HTMLElement;
  skeleton: HTMLElement;
  fallbackPre: HTMLElement;
  source: string;
  initialWrap: boolean;
}

interface MonacoViewerController {
  setWrap: (enabled: boolean) => void;
  setMap: (enabled: boolean) => void;
  dispose: () => void;
}

export async function mountMonacoViewer({
  container,
  skeleton,
  fallbackPre,
  source,
  initialWrap,
}: MountMonacoViewerOptions): Promise<MonacoViewerController> {
  const timeout = new Promise<never>((_, reject) => {
    window.setTimeout(() => reject(new Error('timeout')), 8000);
  });

  const monaco = await Promise.race([loader.init(), timeout]);
  monaco.editor.defineTheme('catppuccin-frappe', catppuccinFrappe);

  const isMobile = window.innerWidth < 768;

  const editor = monaco.editor.create(container, {
    value: source,
    language: 'markdown',
    theme: 'catppuccin-frappe',
    readOnly: true,
    automaticLayout: true,
    wordWrap: initialWrap ? 'on' : 'off',
    lineNumbers: 'on',
    lineNumbersMinChars: isMobile ? 3 : 4,
    folding: !isMobile,
    smoothScrolling: true,
    fontSize: isMobile ? 12 : 13,
    lineHeight: isMobile ? 20 : 22,
    fontFamily: "'Google Sans Mono', ui-monospace, SFMono-Regular, Menlo, monospace",
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

  skeleton.hidden = true;
  fallbackPre.style.display = 'none';
  container.style.display = 'block';
  editor.setScrollTop(0);
  editor.setPosition({ lineNumber: 1, column: 1 });

  return {
    setWrap(enabled: boolean) {
      editor.updateOptions({ wordWrap: enabled ? 'on' : 'off' });
      window.setTimeout(sizeContainer, 50);
    },
    setMap(enabled: boolean) {
      editor.updateOptions({ minimap: { enabled } });
    },
    dispose() {
      window.removeEventListener('resize', sizeContainer);
      editor.dispose();
    },
  };
}
