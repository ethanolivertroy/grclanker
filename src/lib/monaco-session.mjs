/** @typedef {{wrap:boolean,map:boolean}} ViewerOptions */
/** @typedef {{setOptions:(options:ViewerOptions)=>void,layout:()=>void,focus:()=>void,dispose:()=>void}} ViewerController */

/**
 * Own one asynchronous editor mount. Options remain current while its loader is
 * pending, and disposal prevents a late result from publishing into a dead view.
 * @param {{mount:(signal:AbortSignal)=>Promise<ViewerController>,options:ViewerOptions,onReady:()=>void,onError:(error:unknown)=>void}} input
 */
export function createMonacoSession({ mount, options, onReady, onError }) {
  const lifetime = new AbortController();
  /** @type {ViewerController | undefined} */
  let controller;
  const ready = Promise.resolve().then(() => {
    lifetime.signal.throwIfAborted();
    return mount(lifetime.signal);
  }).then((mounted) => {
    if (lifetime.signal.aborted) {
      mounted.dispose();
      return;
    }
    controller = mounted;
    controller.setOptions(options);
    onReady();
  }).catch((error) => {
    controller?.dispose();
    controller = undefined;
    if (!lifetime.signal.aborted) onError(error);
  });

  return {
    ready,
    /** @param {ViewerOptions} next */
    updateOptions(next) {
      options = next;
      controller?.setOptions(next);
    },
    layout: () => controller?.layout(),
    focus: () => controller?.focus(),
    dispose() {
      lifetime.abort();
      controller?.dispose();
      controller = undefined;
    },
  };
}
