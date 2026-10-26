import {createRequire} from 'node:module';
import {performance} from 'node:perf_hooks';

const require = createRequire(import.meta.url);
const TABLE = 'pso_state';
const MAX_KEY_BYTES = 1024;
const MAX_VALUE_BYTES = 3 * 1024 * 1024;
const MAX_SCAN_BYTES = 8 * 1024 * 1024;
const MAX_EXPIRY_MS = Date.UTC(2100, 0, 1);
const QUERY = Object.freeze({
  get: `DECLARE $key AS Utf8;
DECLARE $now AS Timestamp;
SELECT key, value, expires_at AS expiry FROM pso_state
WHERE key = $key AND (expires_at IS NULL OR expires_at > $now);`,
  put: `DECLARE $key AS Utf8;
DECLARE $value AS Utf8;
DECLARE $expiry AS Timestamp?;
UPSERT INTO pso_state (key, value, expires_at) VALUES ($key, $value, $expiry);`,
  delete: `DECLARE $key AS Utf8;
DELETE FROM pso_state WHERE key = $key;`,
  scan: `DECLARE $prefix AS Utf8;
DECLARE $upper AS Utf8;
DECLARE $after AS Utf8;
DECLARE $now AS Timestamp;
DECLARE $limit AS Uint64;
SELECT key, value, expires_at AS expiry FROM pso_state
WHERE key >= $prefix AND key < $upper AND key > $after
AND (expires_at IS NULL OR expires_at > $now)
ORDER BY key ASC LIMIT $limit;`,
  commit: 'SELECT CAST(1 AS Int32) AS committed;'
});

export class YdbDatabaseError extends Error {
  constructor(code) {
    super(code);
    this.name = 'YdbDatabaseError';
    this.code = code;
  }
}

function fail(code) { throw new YdbDatabaseError(code); }
function integer(value, min, max, code) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail(code);
  return value;
}
function validKey(value) {
  if (typeof value !== 'string' || !/^[\x21-\x7e]+$/.test(value) || value.length > MAX_KEY_BYTES) fail('invalid_key');
  return value;
}
function jsonString(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('invalid_value');
  const ancestors = new Set();
  function visit(item, depth) {
    if (depth > 64) fail('invalid_value');
    if (item === null || typeof item === 'string' || typeof item === 'boolean') return;
    if (typeof item === 'number' && Number.isFinite(item)) return;
    if (typeof item !== 'object' || ancestors.has(item)) fail('invalid_value');
    const array = Array.isArray(item);
    if (!array && ![Object.prototype, null].includes(Object.getPrototypeOf(item))) fail('invalid_value');
    if (Object.getOwnPropertySymbols(item).length) fail('invalid_value');
    ancestors.add(item);
    if (array) {
      for (let i = 0; i < item.length; i++) visit(item[i], depth + 1);
    } else {
      for (const key of Object.keys(item)) visit(item[key], depth + 1);
    }
    ancestors.delete(item);
  }
  visit(value, 0);
  const json = JSON.stringify(value);
  if (Buffer.byteLength(json, 'utf8') > MAX_VALUE_BYTES) fail('value_too_large');
  return json;
}
function decodeValue(value) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > MAX_VALUE_BYTES) fail('invalid_record');
  let decoded;
  try { decoded = JSON.parse(value); } catch { fail('invalid_record'); }
  if (!decoded || typeof decoded !== 'object' || Array.isArray(decoded)) fail('invalid_record');
  return decoded;
}
function isStatus(sdk, error, name) {
  return error instanceof sdk.YdbError && error.constructor.status === sdk.StatusCode[name];
}
function safeDbError(sdk, error) {
  // Database errors may contain SQL parameters. Never expose their message/cause.
  if (error instanceof YdbDatabaseError) return error;
  if (error instanceof sdk.YdbError) {
    const out = new YdbDatabaseError('database_unavailable');
    out.status = error.constructor.status;
    return out;
  }
  return new YdbDatabaseError('database_unavailable');
}
function remaining(deadline) {
  const ms = Math.floor(deadline - performance.now());
  if (ms <= 0) fail('database_deadline');
  return ms;
}

/**
 * Transactional JSON KV adapter for ydb-sdk 5.11.1, Table API.
 *
 * Call ensureSchema() explicitly from a separate authenticated bootstrap step.
 * The driver must use a quiet logger: SDK trace logging includes query parameters.
 * Callback execution may repeat after a definite YDB ABORTED response. It MUST
 * contain database work only; send push/network messages after transaction resolves.
 * expiresMs is an absolute Unix millisecond timestamp; 0 means no expiry.
 * Never use a returned transaction outside its callback. Await every operation.
 * The caller owns the driver and must destroy it at the end of a function request.
 */
export function createYdbDatabase({
  driver, now = Date.now, sdk: suppliedSdk,
  timeoutMs = 15000, operationTimeoutMs = 5000, maxAttempts = 4,
  maxOperations = 512, sleep = ms => new Promise(resolve => setTimeout(resolve, ms)),
  random = Math.random
} = {}) {
  const sdk = suppliedSdk || require('ydb-sdk');
  if (!driver?.tableClient?.withSession || typeof now !== 'function') fail('invalid_database_config');
  integer(timeoutMs, 1, 120000, 'invalid_database_config');
  integer(operationTimeoutMs, 1, timeoutMs, 'invalid_database_config');
  integer(maxAttempts, 1, 8, 'invalid_database_config');
  integer(maxOperations, 1, 4096, 'invalid_database_config');
  let poisoned = false;
  const wallNow = () => integer(now(), 0, MAX_EXPIRY_MS, 'invalid_clock');
  const opParams = (deadline, cap = operationTimeoutMs) => {
    const ms = Math.max(1, Math.min(cap, remaining(deadline)));
    const duration = {seconds: Math.floor(ms / 1000), nanos: (ms % 1000) * 1000000};
    return new sdk.OperationParams().withSyncMode().withOperationTimeout(duration).withCancelAfter(duration);
  };
  const querySettings = deadline => new sdk.ExecuteQuerySettings()
    .withIdempotent(false).withOperationParams(opParams(deadline));

  async function bounded(work) {
    if (poisoned) fail('database_closed');
    const deadline = performance.now() + timeoutMs;
    const guard = {active: true};
    let timer;
    try {
      return await Promise.race([
        Promise.resolve().then(() => work(deadline, guard)),
        new Promise((_, reject) => {
          timer = setTimeout(() => {
            guard.active = false;
            // A delayed commit might have succeeded. Never retry or reuse this
            // adapter while a timed-out request could still be in flight.
            poisoned = true;
            reject(new YdbDatabaseError('database_deadline'));
          }, timeoutMs);
        })
      ]);
    } finally {
      guard.active = false;
      clearTimeout(timer);
    }
  }

  function nativeRows(result) {
    const set = result?.resultSets?.[0];
    if (!set || set.truncated) fail(set?.truncated ? 'result_limit' : 'invalid_result');
    const rows = sdk.TypedData.createNativeObjects(set);
    if (!Array.isArray(rows)) fail('invalid_result');
    return rows;
  }
  function liveRow(row) {
    if (!row || typeof row.key !== 'string') fail('invalid_record');
    if (row.expiry !== null) {
      if (!(row.expiry instanceof Date) || !Number.isFinite(row.expiry.getTime())) fail('invalid_record');
      if (row.expiry.getTime() <= wallNow()) return false;
    }
    return true;
  }

  async function attempt(session, callback, deadline, guard) {
    let txId, accepting = true, open = true, commitStarted = false;
    let operations = 0, failed = null, tail = Promise.resolve();
    const check = () => {
      if (!guard.active || !open) fail('transaction_closed');
      remaining(deadline);
    };
    const execute = async (query, params) => {
      check();
      if (++operations > maxOperations) fail('operation_limit');
      const control = txId ? {txId, commitTx: false} : {beginTx: {serializableReadWrite: {}}, commitTx: false};
      const result = await session.executeQuery(query, params, control, querySettings(deadline));
      if (!txId) {
        txId = result?.txMeta?.id;
        if (typeof txId !== 'string' || !txId) fail('invalid_transaction');
      } else if (result?.txMeta?.id && result.txMeta.id !== txId) fail('invalid_transaction');
      check();
      return result;
    };
    const enqueue = operation => {
      if (!accepting || !guard.active || !open) return Promise.reject(new YdbDatabaseError('transaction_closed'));
      const result = tail.then(() => {
        if (failed) throw failed;
        check();
        return operation();
      });
      // Also observe rejected operations if a caller mistakenly ignores one.
      tail = result.then(() => {}, error => { failed ||= error; });
      return result;
    };
    const tx = Object.freeze({
      get(key) {
        return enqueue(async () => {
          validKey(key);
          const rows = nativeRows(await execute(QUERY.get, {
            $key: sdk.TypedValues.utf8(key), $now: sdk.TypedValues.timestamp(new Date(wallNow()))
          }));
          if (rows.length > 1 || (rows.length && rows[0].key !== key)) fail('invalid_result');
          return rows.length && liveRow(rows[0]) ? decodeValue(rows[0].value) : null;
        });
      },
      put(key, value, expiresMs = 0) {
        // Snapshot synchronously: later changes to the caller's object must not
        // change which value is written when queued operations are executed.
        let json, invalid;
        try { validKey(key); json = jsonString(value); integer(expiresMs, 0, MAX_EXPIRY_MS, 'invalid_expiry'); }
        catch (error) { invalid = error; }
        return enqueue(async () => {
          if (invalid) throw invalid;
          await execute(QUERY.put, {
            $key: sdk.TypedValues.utf8(key), $value: sdk.TypedValues.utf8(json),
            $expiry: expiresMs === 0 ? sdk.TypedValues.optionalNull(sdk.Types.TIMESTAMP)
              : sdk.TypedValues.optional(sdk.TypedValues.timestamp(new Date(expiresMs)))
          });
        });
      },
      delete(key) {
        return enqueue(async () => {
          validKey(key);
          await execute(QUERY.delete, {$key: sdk.TypedValues.utf8(key)});
        });
      },
      scan(prefix, {limit = 1000, after = null} = {}) {
        return enqueue(async () => {
          validKey(prefix);
          integer(limit, 1, 1000, 'invalid_scan_limit');
          if (after !== null && (!validKey(after).startsWith(prefix))) fail('invalid_cursor');
          const upper = prefix.slice(0, -1) + String.fromCharCode(prefix.charCodeAt(prefix.length - 1) + 1);
          const output = [];
          let cursor = after || '', bytes = 0;
          while (output.length < limit) {
            const count = limit - output.length;
            const rows = nativeRows(await execute(QUERY.scan, {
              $prefix: sdk.TypedValues.utf8(prefix), $upper: sdk.TypedValues.utf8(upper),
              $after: sdk.TypedValues.utf8(cursor), $limit: sdk.TypedValues.uint64(count),
              $now: sdk.TypedValues.timestamp(new Date(wallNow()))
            }));
            if (rows.length > count) fail('invalid_result');
            for (const row of rows) {
              if (typeof row.key !== 'string' || !row.key.startsWith(prefix) || row.key <= cursor) fail('invalid_result');
              cursor = row.key;
              if (!liveRow(row)) continue;
              if (typeof row.value !== 'string') fail('invalid_record');
              bytes += Buffer.byteLength(row.value, 'utf8');
              if (bytes > MAX_SCAN_BYTES) fail('result_limit');
              output.push({key: row.key, value: decodeValue(row.value)});
            }
            if (rows.length < count) break;
          }
          return output;
        });
      }
    });
    try {
      const result = await callback(tx);
      accepting = false;
      await tail;
      if (failed) throw failed;
      check();
      if (txId) {
        // SDK commitTransaction() retries transport failures internally. Use
        // ExecuteDataQuery commitTx with idempotent:false instead: exactly one
        // commit attempt, and never repeat an uncertain commit.
        commitStarted = true;
        await session.executeQuery(QUERY.commit, {}, {txId, commitTx: true}, querySettings(deadline));
      }
      check();
      return result;
    } catch (error) {
      accepting = false;
      open = false;
      await tail;
      if (txId && !commitStarted && guard.active && !isStatus(sdk, error, 'ABORTED')) {
        // Rollback is safe to repeat. Its SDK retries cannot cause a commit;
        // the outer watchdog still bounds the time visible to the caller.
        try {
          await session.rollbackTransaction({txId}, new sdk.RollbackTransactionSettings()
            .withOperationParams(opParams(deadline, 1000)));
        } catch { /* Preserve the original failure without logging it. */ }
      }
      throw error;
    } finally {
      accepting = false;
      open = false;
    }
  }

  async function transaction(callback) {
    if (typeof callback !== 'function') fail('invalid_callback');
    return bounded(async (deadline, guard) => {
      for (let index = 0; index < maxAttempts; index++) {
        if (!guard.active) fail('transaction_closed');
        try {
          return await driver.tableClient.withSession(
            session => attempt(session, callback, deadline, guard), remaining(deadline)
          );
        } catch (error) {
          if (!guard.active) fail('database_deadline');
          if (!isStatus(sdk, error, 'ABORTED')) {
            if (error instanceof sdk.YdbError || typeof error?.code === 'number') throw safeDbError(sdk, error);
            throw error;
          }
          if (index + 1 === maxAttempts) {
            const out = new YdbDatabaseError('database_conflict');
            out.status = sdk.StatusCode.ABORTED;
            throw out;
          }
          const delay = Math.min(200, 10 * 2 ** index) * (0.5 + 0.5 * random());
          if (remaining(deadline) <= delay) fail('database_deadline');
          await sleep(delay);
        }
      }
    });
  }

  async function ensureSchema() {
    return bounded(async (deadline, guard) => {
      try {
        return await driver.tableClient.withSession(async session => {
          let description;
          try {
            description = await session.describeTable(TABLE, new sdk.DescribeTableSettings().withOperationParams(opParams(deadline)));
          } catch (error) {
            if (!isStatus(sdk, error, 'NOT_FOUND') && !isStatus(sdk, error, 'SCHEME_ERROR')) throw error;
            if (!guard.active) fail('database_deadline');
            const table = new sdk.TableDescription()
              // The legacy Table API uses nullable types in its schema. The
              // adapter always writes non-null keys/values and rejects null
              // values read from storage; only expires_at intentionally NULLs.
              .withColumn(new sdk.Column('key', sdk.Types.optional(sdk.Types.UTF8)))
              .withColumn(new sdk.Column('value', sdk.Types.optional(sdk.Types.UTF8)))
              .withColumn(new sdk.Column('expires_at', sdk.Types.optional(sdk.Types.TIMESTAMP)))
              .withPrimaryKey('key').withTtl('expires_at', 0);
            table.storeType = sdk.Ydb?.Table?.StoreType?.STORE_TYPE_ROW ?? 1;
            try {
              await session.createTable(TABLE, table, new sdk.CreateTableSettings().withOperationParams(opParams(deadline)));
            } catch (created) {
              if (!isStatus(sdk, created, 'ALREADY_EXISTS')) throw created;
            }
            if (!guard.active) fail('database_deadline');
            description = await session.describeTable(TABLE, new sdk.DescribeTableSettings().withOperationParams(opParams(deadline)));
          }
          const columns = description?.columns || [];
          const type = name => columns.find(column => column.name === name)?.type;
          const ttl = description?.ttlSettings?.dateTypeColumn;
          if (columns.length !== 3 || description?.primaryKey?.length !== 1 || description.primaryKey[0] !== 'key'
            || columns.some(column => column.notNull === true)
            || ![undefined, null, 0, 1].includes(description.storeType)
            || type('key')?.optionalType?.item?.typeId !== sdk.Types.UTF8.typeId
            || type('value')?.optionalType?.item?.typeId !== sdk.Types.UTF8.typeId
            || type('expires_at')?.optionalType?.item?.typeId !== sdk.Types.TIMESTAMP.typeId
            || !ttl || ttl.columnName !== 'expires_at' || Number(ttl.expireAfterSeconds || 0) !== 0
            || description.ttlSettings.valueSinceUnixEpoch) fail('schema_mismatch');
          if (!guard.active) fail('database_deadline');
          return {table: TABLE, ready: true};
        }, remaining(deadline));
      } catch (error) { throw safeDbError(sdk, error); }
    });
  }

  return Object.freeze({transaction, ensureSchema});
}

/** Explicit bootstrap entry point; never runs during normal transaction calls. */
export function ensureSchema(options) {
  return createYdbDatabase(options).ensureSchema();
}
