// Only the application shell is updated. Device keys and other stored data are
// never read, replaced or deleted here. The user chooses when to reload the UI.
export function installAppUpdates({
  navigator: nav = globalThis.navigator,
  document: doc = globalThis.document,
  onReady = () => {},
  onStatus = () => {},
  now = () => Date.now(),
  timeoutMs = 12000,
  setTimeout: later = globalThis.setTimeout,
  clearTimeout: cancel = globalThis.clearTimeout
} = {}) {
  const sw = nav?.serviceWorker;
  let activeCheck, lastCheck = -Infinity, announced = false;
  let baselineWorker = sw?.controller || null;
  const watched = new WeakSet();
  const status = value => onStatus(value);
  const announce = worker => {
    if (!worker) return;
    // The first installation establishes the baseline. Once it controls this
    // page, a later worker in the same session is a real update.
    if (!baselineWorker) { baselineWorker = worker; return; }
    if (worker === baselineWorker) return;
    if (!announced) { announced = true; onReady(); }
    status('ready');
  };
  const watch = worker => {
    if (!worker || watched.has(worker)) return;
    watched.add(worker);
    const changed = () => {
      if (worker.state === 'activated') announce(worker);
    };
    worker.addEventListener?.('statechange', changed);
    changed();
  };
  sw?.addEventListener?.('controllerchange', () => announce(sw.controller));
  const registered = sw
    ? Promise.resolve().then(() => sw.register('./sw.js', {updateViaCache:'none'})).then(value => {
      const observe = () => { watch(value.installing); watch(value.waiting); };
      value.addEventListener?.('updatefound', observe);
      observe();
      return value;
    })
    : Promise.reject(new Error('Service workers are unavailable'));
  const ready = registered.then(() => sw.ready);
  // Both promises remain rejectable for callers, without unhandled rejections
  // when the caller only uses the visible update controls.
  registered.catch(() => {});
  ready.catch(() => {});

  function waitForInstallation(value) {
    const worker = value.installing || value.waiting;
    if (!worker) return Promise.resolve();
    watch(worker);
    if (worker.state === 'redundant') return Promise.reject(new Error('Update installation failed'));
    if (worker.state === 'activated') return Promise.resolve();
    return new Promise((resolve, reject) => {
      const changed = () => {
        if (['activated','redundant'].includes(worker.state)) {
          worker.removeEventListener?.('statechange', changed);
          if (worker.state === 'redundant') reject(new Error('Update installation failed'));
          else resolve();
        }
      };
      worker.addEventListener?.('statechange', changed);
      changed();
    });
  }
  function check(automatic = false) {
    if (activeCheck) return activeCheck;
    if (automatic && now() - lastCheck < 60000) return Promise.resolve();
    if (nav?.onLine === false) { status('offline'); return Promise.resolve(); }
    lastCheck = now();
    if (announced) { status('ready'); return Promise.resolve(); }
    status('checking');
    let timer;
    const timeout = new Promise((_, reject) => {
      timer = later(() => reject(new Error('Update check timed out')), timeoutMs);
    });
    const operation = registered.then(async value => {
      await value.update();
      watch(value.installing); watch(value.waiting);
      await waitForInstallation(value);
    });
    activeCheck = Promise.race([operation, timeout]).then(() => {
      status(announced ? 'ready' : 'current');
    }).catch(() => status(nav?.onLine === false ? 'offline' : 'unavailable'))
      .finally(() => { cancel(timer); activeCheck = null; });
    return activeCheck;
  }
  doc?.addEventListener?.('visibilitychange', () => {
    if (!doc.hidden) void check(true);
  });
  globalThis.addEventListener?.('online', () => { void check(true); });
  void check(true);
  return {ready, check:() => check(false)};
}
