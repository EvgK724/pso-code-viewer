import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {randomUUID} from 'node:crypto';
import {createYdbDatabase, ensureSchema, YdbDatabaseError} from './ydb-database.mjs';

const require = createRequire(import.meta.url);
const NOW = Date.UTC(2026, 9, 25);
class YdbError extends Error {}
const StatusCode = {ABORTED: 400040, UNAVAILABLE: 400050, SCHEME_ERROR: 400070,
  TIMEOUT: 400090, ALREADY_EXISTS: 400130, NOT_FOUND: 400140, UNDETERMINED: 400170};
const error = (status, message = 'private database details') => {
  class SpecificError extends YdbError { static status = status; }
  return new SpecificError(message);
};
class Settings {
  withOperationParams(value) { this.operationParams = value; return this; }
  withIdempotent(value) { this.idempotent = value; return this; }
  withSyncMode() { return this; }
  withOperationTimeout(value) { this.operationTimeout = value; return this; }
  withCancelAfter(value) { this.cancelAfter = value; return this; }
}
const Types = {UTF8: {typeId: 4608}, TIMESTAMP: {typeId: 50}, optional: item => ({optionalType: {item}})};
class TableDescription {
  columns = []; primaryKey = [];
  withColumn(column) { this.columns.push(column); return this; }
  withPrimaryKey(key) { this.primaryKey.push(key); return this; }
  withTtl(columnName, expireAfterSeconds) { this.ttlSettings = {dateTypeColumn: {columnName, expireAfterSeconds}}; return this; }
}
const sdk = {
  YdbError, StatusCode, Types, TableDescription,
  Column: class { constructor(name, type) { this.name = name; this.type = type; } },
  ExecuteQuerySettings: Settings, OperationParams: Settings, RollbackTransactionSettings: Settings,
  DescribeTableSettings: Settings, CreateTableSettings: Settings,
  TypedValues: {utf8: x => x, timestamp: x => x, uint64: x => x, optional: x => x, optionalNull: () => null},
  TypedData: {createNativeObjects: set => set.rows}
};
function schema() {
  return new TableDescription().withColumn(new sdk.Column('key', Types.optional(Types.UTF8)))
    .withColumn(new sdk.Column('value', Types.optional(Types.UTF8)))
    .withColumn(new sdk.Column('expires_at', Types.optional(Types.TIMESTAMP)))
    .withPrimaryKey('key').withTtl('expires_at', 0);
}

function fixture(options = {}) {
  let version = 0, sequence = 0, clock = NOW;
  const data = new Map(), calls = [], commits = [], rollbacks = [], sessions = [];
  const f = {data, calls, commits, rollbacks, sessions, schema: null, creates: 0,
    commitFailures: [], queryFailures: [], truncated: false, beforeQuery: null,
    setClock(value) { clock = value; }};
  const clone = map => new Map([...map].map(([key, value]) => [key, structuredClone(value)]));
  const driver = {tableClient: {async withSession(callback) {
    const session = {id: ++sequence, current: null,
      async executeQuery(query, params, control, settings) {
        calls.push({query, params, control: {...control}, settings});
        assert.equal(settings.idempotent, false, 'implicit SDK query retries must remain off');
        if (f.beforeQuery) await f.beforeQuery(query, params, control);
        if (f.queryFailures.length) throw f.queryFailures.shift();
        if (control.beginTx) {
          assert.deepEqual(control.beginTx, {serializableReadWrite: {}});
          assert.equal(control.commitTx, false);
          this.current = {id: 'tx-' + this.id, version, data: clone(data), dirty: false};
        }
        const tx = this.current;
        assert.ok(tx, 'all database queries share an explicit transaction');
        if (control.txId) assert.equal(control.txId, tx.id);
        if (control.commitTx) {
          commits.push(tx.id);
          const failure = f.commitFailures.shift();
          if (failure?.apply) {
            data.clear(); for (const [key, value] of tx.data) data.set(key, value); version++;
          }
          if (failure) throw failure.error;
          if (tx.version !== version) throw error(StatusCode.ABORTED);
          if (tx.dirty) { data.clear(); for (const [key, value] of tx.data) data.set(key, value); version++; }
          this.current = null;
          return {resultSets: [{rows: [{committed: 1}]}]};
        }
        let rows = [];
        if (query.includes('UPSERT INTO')) {
          tx.data.set(params.$key, {key: params.$key, value: params.$value, expiry: params.$expiry}); tx.dirty = true;
        } else if (query.includes('DELETE FROM')) {
          tx.data.delete(params.$key); tx.dirty = true;
        } else if (query.includes('ORDER BY key ASC')) {
          rows = [...tx.data.values()].filter(row => row.key >= params.$prefix && row.key < params.$upper
            && row.key > params.$after && (row.expiry === null || row.expiry > params.$now))
            .sort((a, b) => a.key < b.key ? -1 : a.key > b.key ? 1 : 0).slice(0, params.$limit);
        } else {
          const row = tx.data.get(params.$key);
          if (row && (row.expiry === null || row.expiry > params.$now)) rows.push(row);
        }
        return {txMeta: {id: tx.id}, resultSets: [{rows, truncated: f.truncated}]};
      },
      async rollbackTransaction(control) { rollbacks.push(control.txId); this.current = null; },
      async describeTable(name) { assert.equal(name, 'pso_state'); if (!f.schema) throw error(StatusCode.SCHEME_ERROR); return f.schema; },
      async createTable(name, description) {
        assert.equal(name, 'pso_state'); f.creates++;
        if (f.schema) throw error(StatusCode.ALREADY_EXISTS);
        f.schema = description;
      }
    };
    sessions.push(session);
    return callback(session);
  }}};
  f.driver = driver;
  f.db = createYdbDatabase({driver, sdk, now: () => clock, sleep: async () => {}, random: () => 0, ...options});
  f.seed = (key, value, expires = 0) => data.set(key, {key, value: JSON.stringify(value), expiry: expires ? new Date(expires) : null});
  return f;
}

test('writes, reads own writes, deletes and snapshots queued object values atomically', async () => {
  const f = fixture();
  const result = await f.db.transaction(async tx => {
    const record = {state: 'pending', nested: {number: 1}};
    const writing = tx.put('member/one', record);
    record.nested.number = 99;
    await writing;
    assert.deepEqual(await tx.get('member/one'), {state: 'pending', nested: {number: 1}});
    await tx.put('member/two', {state: 'active'});
    await tx.delete('member/one');
    assert.equal(await tx.get('member/one'), null);
    return 'done';
  });
  assert.equal(result, 'done');
  assert.equal(f.commits.length, 1);
  assert.equal(f.data.size, 1);
  assert.equal(f.data.has('member/two'), true);
  assert.equal(f.data.get('member/two').expiry, null, 'non-expiring records never use epoch as TTL');
});

test('callback failure rolls back; a caught failed operation also prevents partial commit', async () => {
  const f = fixture();
  await assert.rejects(f.db.transaction(async tx => {
    await tx.put('member/one', {state: 'active'});
    throw new Error('cancelled by caller');
  }), /cancelled by caller/);
  assert.equal(f.data.size, 0);
  assert.equal(f.rollbacks.length, 1);
  await assert.rejects(f.db.transaction(async tx => {
    await tx.put('member/one', {state: 'active'});
    await tx.put('bad key', {state: 'active'}).catch(() => {});
  }), {code: 'invalid_key'});
  assert.equal(f.commits.length, 0);
});

test('TTL is checked logically at equality before cleanup, scans filter before limit', async () => {
  const f = fixture();
  f.seed('index/00', {n: 0}, NOW);
  f.seed('index/01', {n: 1}, NOW - 1);
  f.seed('index/02', {n: 2}, NOW + 1);
  f.seed('index/03', {n: 3});
  f.seed('index/04', {n: 4});
  await f.db.transaction(async tx => {
    assert.equal(await tx.get('index/00'), null);
    assert.equal(await tx.get('index/01'), null);
    assert.deepEqual(await tx.scan('index/', {limit: 2}), [
      {key: 'index/02', value: {n: 2}}, {key: 'index/03', value: {n: 3}}
    ]);
    assert.deepEqual(await tx.scan('index/', {after: 'index/03'}), [{key: 'index/04', value: {n: 4}}]);
  });
  assert.equal(f.data.size, 5, 'logical expiry is independent of physical TTL deletion');
});

test('records expiring while a query is in flight are not returned, and scan still fills its page', async () => {
  const f = fixture();
  f.seed('index/00', {n: 0}, NOW + 1);
  f.seed('index/01', {n: 1});
  f.beforeQuery = async () => f.setClock(NOW + 2);
  assert.deepEqual(await f.db.transaction(tx => tx.scan('index/', {limit: 1})), [{key: 'index/01', value: {n: 1}}]);
  f.setClock(NOW);
  assert.equal(await f.db.transaction(tx => tx.get('index/00')), null);
});

test('scan includes exact prefix key and stable ASCII bounds, rejects foreign cursors', async () => {
  const f = fixture();
  for (const key of ['a~', 'a~0', 'a~~', 'b0']) f.seed(key, {key});
  const rows = await f.db.transaction(tx => tx.scan('a~'));
  assert.deepEqual(rows.map(row => row.key), ['a~', 'a~0', 'a~~']);
  await assert.rejects(f.db.transaction(tx => tx.scan('a~', {after: 'b0'})), {code: 'invalid_cursor'});
  for (const limit of [0, -1, 1001, Infinity, 1.5]) {
    await assert.rejects(f.db.transaction(tx => tx.scan('a~', {limit})), {code: 'invalid_scan_limit'});
  }
});

test('keys, cursors and JSON remain parameters even when they contain SQL punctuation', async () => {
  const f = fixture();
  const key = "member/'`;$key";
  const value = {text: "'; DELETE FROM pso_state; --", surname: 'Синтетический'};
  await f.db.transaction(async tx => { await tx.put(key, value); assert.deepEqual(await tx.get(key), value); });
  for (const call of f.calls) {
    assert.equal(call.query.includes(key), false);
    assert.equal(call.query.includes(value.text), false);
  }
});

test('only definite ABORTED retries the full callback with fresh state', async () => {
  const f = fixture();
  f.commitFailures.push({error: error(StatusCode.ABORTED)});
  let runs = 0;
  await f.db.transaction(async tx => { runs++; const old = await tx.get('counter/one'); await tx.put('counter/one', {n: (old?.n || 0) + 1}); });
  assert.equal(runs, 2);
  assert.equal(JSON.parse(f.data.get('counter/one').value).n, 1);
  assert.equal(f.sessions.length, 2);
});

test('ABORTED during an operation skips rollback of the already-invalidated transaction', async () => {
  const f = fixture();
  let injected = false;
  f.beforeQuery = async query => {
    if (!injected && query.includes('UPSERT')) { injected = true; f.queryFailures.push(error(StatusCode.ABORTED)); }
  };
  await f.db.transaction(async tx => { await tx.get('counter/one'); await tx.put('counter/one', {n: 1}); });
  assert.equal(f.sessions.length, 2);
  assert.equal(f.rollbacks.length, 0);
  assert.equal(JSON.parse(f.data.get('counter/one').value).n, 1);
});

test('concurrent serializable read-modify-write retries a conflict rather than losing an update', async () => {
  const f = fixture();
  f.seed('counter/one', {n: 0});
  let firstReads = 0, release;
  const barrier = new Promise(resolve => { release = resolve; });
  const increment = () => f.db.transaction(async tx => {
    const old = await tx.get('counter/one');
    if (++firstReads <= 2) { if (firstReads === 2) release(); await barrier; }
    await tx.put('counter/one', {n: old.n + 1});
  });
  await Promise.all([increment(), increment()]);
  assert.equal(JSON.parse(f.data.get('counter/one').value).n, 2);
  assert.equal(f.commits.length, 3);
});

test('uncertain commit is never replayed even if the server applied it', async () => {
  for (const status of [StatusCode.UNDETERMINED, StatusCode.UNAVAILABLE, StatusCode.TIMEOUT]) {
    const f = fixture();
    f.commitFailures.push({error: error(status), apply: true});
    let runs = 0;
    await assert.rejects(f.db.transaction(async tx => { runs++; await tx.put('counter/one', {n: 1}); }),
      e => e.code === 'database_unavailable' && !e.message.includes('private') && !e.cause);
    assert.equal(runs, 1);
    assert.equal(f.commits.length, 1);
    assert.equal(JSON.parse(f.data.get('counter/one').value).n, 1);
  }
});

test('retry bound and fake ABORTED error fail closed', async () => {
  const f = fixture({maxAttempts: 2});
  f.commitFailures.push({error: error(StatusCode.ABORTED)}, {error: error(StatusCode.ABORTED)});
  await assert.rejects(f.db.transaction(tx => tx.put('counter/one', {n: 1})), {code: 'database_conflict'});
  assert.equal(f.sessions.length, 2);
  assert.equal(f.data.size, 0);
  let runs = 0;
  const pretend = Object.assign(new Error('business failure'), {code: StatusCode.ABORTED});
  await assert.rejects(f.db.transaction(() => { runs++; throw pretend; }), {code: 'database_unavailable'});
  assert.equal(runs, 1);
});

test('late callback after watchdog cannot commit; timed-out adapter cannot be reused', async () => {
  const f = fixture({timeoutMs: 25, operationTimeoutMs: 15});
  let resume;
  const waiting = new Promise(resolve => { resume = resolve; });
  const pending = f.db.transaction(async tx => { await tx.put('member/one', {state: 'active'}); await waiting; });
  await assert.rejects(pending, {code: 'database_deadline'});
  resume();
  await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(f.data.size, 0);
  assert.equal(f.commits.length, 0);
  await assert.rejects(f.db.transaction(tx => tx.get('member/one')), {code: 'database_closed'});
});

test('retained transaction cannot access data after commit and empty transaction does not write', async () => {
  const f = fixture();
  let retained;
  assert.equal(await f.db.transaction(tx => { retained = tx; return 42; }), 42);
  assert.equal(f.calls.length, 0);
  await assert.rejects(retained.get('member/one'), {code: 'transaction_closed'});
});

test('malformed JSON, lossy JSON, invalid expiry and truncated result cannot produce success', async () => {
  const f = fixture();
  const cyclic = {}; cyclic.self = cyclic;
  for (const value of [{a: undefined}, {a: NaN}, {a: Infinity}, {a: 1n}, cyclic, null, [], {date: new Date()}]) {
    await assert.rejects(f.db.transaction(tx => tx.put('member/one', value)), {code: 'invalid_value'});
  }
  for (const expires of [-1, NaN, '123', 1.5]) {
    await assert.rejects(f.db.transaction(tx => tx.put('member/one', {}, expires)), {code: 'invalid_expiry'});
  }
  f.data.set('member/bad', {key: 'member/bad', value: '{broken', expiry: null});
  await assert.rejects(f.db.transaction(tx => tx.get('member/bad')), {code: 'invalid_record'});
  f.truncated = true;
  await assert.rejects(f.db.transaction(tx => tx.scan('member/')), {code: 'result_limit'});
});

test('operation and value size bounds prevent unbounded requests', async () => {
  const f = fixture({maxOperations: 1});
  await assert.rejects(f.db.transaction(async tx => { await tx.put('member/a', {}); await tx.put('member/b', {}); }), {code: 'operation_limit'});
  assert.equal(f.data.size, 0);
  await assert.rejects(f.db.transaction(tx => tx.put('member/a', {text: 'x'.repeat(3 * 1024 * 1024)})), {code: 'value_too_large'});
});

test('schema bootstrap is explicit and idempotent; mismatched TTL or schema is not changed', async () => {
  const f = fixture();
  assert.equal(f.creates, 0);
  assert.deepEqual(await f.db.ensureSchema(), {table: 'pso_state', ready: true});
  assert.equal(f.creates, 1);
  assert.deepEqual(await ensureSchema({driver: f.driver, sdk, now: () => NOW}), {table: 'pso_state', ready: true});
  assert.equal(f.creates, 1);
  f.schema.ttlSettings.dateTypeColumn.expireAfterSeconds = 86400;
  await assert.rejects(f.db.ensureSchema(), {code: 'schema_mismatch'});
  assert.equal(f.creates, 1);
  f.schema = schema();
  f.schema.columns[2].type = Types.TIMESTAMP;
  await assert.rejects(f.db.ensureSchema(), {code: 'schema_mismatch'});
  f.schema = schema();
  f.schema.storeType = 2;
  await assert.rejects(f.db.ensureSchema(), {code: 'schema_mismatch'});
  f.schema = schema();
  f.schema.columns[2].notNull = true;
  await assert.rejects(f.db.ensureSchema(), {code: 'schema_mismatch'});
});

let actualSdk;
try { actualSdk = require('ydb-sdk'); } catch { /* Optional local SDK verification. */ }
test('installed SDK encodes nullable TTL, durations and decodes Timestamp without precision loss', {skip: !actualSdk}, () => {
  const {TypedData, TypedValues, Types, OperationParams, ExecuteQuerySettings, TableDescription, Column} = actualSdk;
  const expiry = new Date(NOW + 1234);
  const rows = TypedData.createNativeObjects({columns: [
    {name: 'key', type: Types.UTF8}, {name: 'value', type: Types.UTF8},
    {name: 'expiry', type: Types.optional(Types.TIMESTAMP)}
  ], rows: [{items: [TypedValues.utf8('member/a').value, TypedValues.utf8('{}').value,
    TypedValues.optional(TypedValues.timestamp(expiry)).value]}]});
  assert.equal(rows[0].expiry.getTime(), expiry.getTime());
  const s = new ExecuteQuerySettings().withIdempotent(false).withOperationParams(new OperationParams()
    .withSyncMode().withOperationTimeout({seconds: 2, nanos: 500000000}).withCancelAfter({seconds: 2, nanos: 500000000}));
  assert.equal(s.idempotent, false);
  assert.equal(s.operationParams.operationTimeout.nanos, 500000000);
  const t = new TableDescription().withColumn(new Column('expires_at', Types.optional(Types.TIMESTAMP))).withTtl('expires_at', 0);
  assert.equal(t.ttlSettings.dateTypeColumn.expireAfterSeconds, 0);
  assert.equal(TypedValues.optionalNull(Types.TIMESTAMP).value.nullFlagValue, 0);
});

// Opt-in only, never enabled by ordinary node --test. Run on a designated test
// database with YDB_ENDPOINT / YDB_DATABASE and the SDK's existing IAM/metadata
// authentication. Creates pso_state if absent; uses synthetic random-prefix data
// only, expires it after 60 seconds and attempts cleanup. Never prints credentials.
test('optional live YDB: schema, transaction, expiry and read-modify-write conflict', {
  skip: process.env.PSO_YDB_INTEGRATION !== '1', timeout: 120000
}, async () => {
  assert.ok(actualSdk, 'Install pinned ydb-sdk first');
  assert.ok(process.env.YDB_ENDPOINT && process.env.YDB_DATABASE, 'Test database endpoint and path required');
  const logger = Object.fromEntries(['trace', 'debug', 'info', 'warn', 'error', 'fatal'].map(x => [x, () => {}]));
  const driver = new actualSdk.Driver({endpoint: process.env.YDB_ENDPOINT, database: process.env.YDB_DATABASE,
    authService: actualSdk.getCredentialsFromEnv(), logger, poolSettings: {minLimit: 1, maxLimit: 4}});
  const prefix = 'integration/' + randomUUID() + '/';
  const db = createYdbDatabase({driver, sdk: actualSdk, timeoutMs: 30000, operationTimeoutMs: 5000, maxAttempts: 8});
  try {
    assert.equal(await driver.ready(10000), true);
    await db.ensureSchema();
    await db.transaction(async tx => {
      await tx.put(prefix + 'counter', {n: 0}, Date.now() + 60000);
      await tx.put(prefix + 'expired', {n: -1}, Date.now() - 1000);
      assert.equal(await tx.get(prefix + 'expired'), null);
      assert.deepEqual(await tx.get(prefix + 'counter'), {n: 0});
    });
    await Promise.all(Array.from({length: 3}, () => db.transaction(async tx => {
      const old = await tx.get(prefix + 'counter');
      await tx.put(prefix + 'counter', {n: old.n + 1}, Date.now() + 60000);
    })));
    assert.deepEqual(await db.transaction(tx => tx.scan(prefix)), [{key: prefix + 'counter', value: {n: 3}}]);
  } finally {
    try { await db.transaction(async tx => { await tx.delete(prefix + 'counter'); await tx.delete(prefix + 'expired'); }); } catch {}
    await driver.destroy();
  }
});
