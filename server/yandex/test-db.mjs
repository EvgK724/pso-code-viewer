/** Transactional memory fixture; production uses ydb-database.mjs. */
export function createMemoryDatabase({now = Date.now} = {}) {
  let rows = new Map(), tail = Promise.resolve();
  const clone = value => JSON.parse(JSON.stringify(value));
  const valid = (row, at) => row && (!row.expiresMs || row.expiresMs > at);
  const db = {
    async transaction(callback) {
      let release;
      const previous = tail;
      tail = new Promise(resolve => { release = resolve; });
      await previous;
      const at = now();
      const working = new Map([...rows].map(([k, row]) => [k, clone(row)]));
      const tx = {
        async get(key) { const row = working.get(key); return valid(row, at) ? clone(row.value) : null; },
        async put(key, value, expiresMs = 0) { working.set(key, {value: clone(value), expiresMs}); },
        async delete(key) { working.delete(key); },
        async scan(prefix, {limit = 1000, after = null} = {}) {
          return [...working].filter(([k, row]) => k.startsWith(prefix) && (!after || k > after) && valid(row, at))
            .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).slice(0, limit)
            .map(([key, row]) => ({key, value: clone(row.value)}));
        }
      };
      try { const result = await callback(tx); rows = working; return result; }
      finally { release(); }
    },
    dump() { return new Map([...rows].filter(([,r]) => valid(r, now())).map(([k,r]) => [k, clone(r.value)])); },
    async seed(key, value, expiresMs = 0) { return db.transaction(tx => tx.put(key, value, expiresMs)); },
    async ensureSchema() { return true; },
  };
  return db;
}
