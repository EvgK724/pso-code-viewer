"""Durable admission queue. Python 3.7+, standard library only."""
import datetime as dt
import hashlib
import json
import sqlite3
import os
import hmac
import urllib.request
import urllib.error

LOCAL_TZ = dt.timezone(dt.timedelta(hours=5), 'Asia/Yekaterinburg')
DESTINATIONS = {'cardio': 'Кардиолог', 'orit': 'Реаниматологи'}
RETENTION_DAYS = 7


def now():
    return dt.datetime.now(LOCAL_TZ)


def in_window(moment):
    return 7 <= moment.astimezone(LOCAL_TZ).hour < 22


def norm(text):
    return ' '.join(text.upper().replace('Ё', 'Е').split())


def connect(path):
    db = sqlite3.connect(str(path), timeout=20)
    db.row_factory = sqlite3.Row
    db.executescript('''
        PRAGMA foreign_keys=ON;
        PRAGMA secure_delete=ON;
        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY, date TEXT NOT NULL, section TEXT NOT NULL,
          rownum INTEGER NOT NULL, name_key TEXT NOT NULL, surname TEXT NOT NULL,
          origin TEXT NOT NULL, routes TEXT NOT NULL, baseline INTEGER NOT NULL,
          active INTEGER NOT NULL DEFAULT 1, review TEXT NOT NULL DEFAULT '',
          stable INTEGER NOT NULL DEFAULT 1, fingerprint TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS event_scope ON events(date,section);
        CREATE TABLE IF NOT EXISTS deliveries (
          id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES events(id),
          destination TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
          message_id TEXT, note TEXT NOT NULL DEFAULT '',
          UNIQUE(event_id,destination));
    ''')
    if meta(db, 'dedup_salt') is None:
        with db:
            set_meta(db, 'dedup_salt', os.urandom(32).hex())
    return db


def meta(db, key, default=None):
    row = db.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
    return row[0] if row else default


def set_meta(db, key, value):
    db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)', (key, str(value)))


def fingerprint(record):
    value = [record['name_key'], record['surname'], record['origin'], record['routes']]
    return hashlib.sha256(json.dumps(value, ensure_ascii=False).encode('utf-8')).hexdigest()


def identity_hash(db, value):
    return hmac.new(bytes.fromhex(meta(db, 'dedup_salt')), value.encode('utf-8'), hashlib.sha256).hexdigest()


def cutoff_date(moment):
    return (moment.astimezone(LOCAL_TZ).date() - dt.timedelta(days=RETENTION_DAYS)).isoformat()


def ingest(db, book, moment, baseline=False):
    """Reconcile one complete, validated snapshot. Never read external links."""
    month = '{:04d}-{:02d}-%'.format(book['year'], book['month'])
    old = list(db.execute('SELECT * FROM events WHERE date LIKE ? ORDER BY active DESC,id', (month,)))
    records = sorted((dict(x, name_key=identity_hash(db, x['name_key'])) for x in book['records']),
                     key=lambda x: (x['date'], x['section'], x['row']))
    cutoff = cutoff_date(moment)
    used = set()
    matches = {}
    # Reserve unchanged active slots across the WHOLE snapshot before matching
    # moves. Otherwise a newly added namesake can steal an older event's ID.
    for active, exact in ((True, True), (True, False), (False, True), (False, False)):
        for index, rec in enumerate(records):
            if index in matches:
                continue
            candidates = [x for x in old if x['id'] not in used
                          and bool(x['active']) == active
                          and x['date'] == rec['date'] and x['section'] == rec['section']
                          and x['name_key'] == rec['name_key']
                          and (not exact or x['rownum'] == rec['row'])]
            if candidates:
                matches[index] = candidates[0]
                used.add(candidates[0]['id'])
    valid_ids = []
    start = meta(db, 'started_date', moment.date().isoformat())
    with db:
        # If a row is temporarily invalid, preserve its event but do not dispatch it.
        invalid = {(x['date'], x['section'], x['row']) for x in book.get('issues', [])}
        db.execute('UPDATE events SET active=0 WHERE date LIKE ?', (month,))
        for index, rec in enumerate(records):
            scope = [x for x in old if x['id'] not in used and x['date'] == rec['date']
                     and x['section'] == rec['section']]
            match = matches.get(index)
            # A record moved elsewhere in the same snapshot is not a renamed patient.
            names_elsewhere = {x['name_key'] for x in records
                               if x['date'] == rec['date'] and x['section'] == rec['section']
                               and x['row'] != rec['row']}
            same_slot = [x for x in scope if x['active'] and x['rownum'] == rec['row']
                         and x['name_key'] not in names_elsewhere]
            review = ''
            if match is None and same_slot:
                previous = same_slot[0]
                delivered = db.execute("SELECT 1 FROM deliveries WHERE event_id=? AND status IN ('sent','sending','uncertain')", (previous['id'],)).fetchone()
                if not previous['baseline'] and not delivered:
                    match = previous  # correction before any send
                else:
                    review = 'Фамилия изменена в уже обработанной строке: проверить, новый ли это пациент.'
            fp = identity_hash(db, fingerprint(rec))
            expired = rec['date'] < cutoff
            stored_surname = '' if expired else rec['surname']
            stored_origin = '' if expired else rec['origin']
            ignored = int(baseline or rec['date'] < start or expired)
            if match is None:
                cur = db.execute('''INSERT INTO events
                    (date,section,rownum,name_key,surname,origin,routes,baseline,active,review,stable,fingerprint)
                    VALUES (?,?,?,?,?,?,?,?,1,?,1,?)''',
                    (rec['date'], rec['section'], rec['row'], rec['name_key'], stored_surname,
                     stored_origin, json.dumps(rec['routes']), ignored, review, fp))
                eid = cur.lastrowid
            else:
                eid = match['id']
                used.add(eid)
                changed = match['fingerprint'] != fp
                stable = 1 if changed or not match['active'] else min(match['stable'] + 1, 100)
                prior_sent = db.execute("SELECT 1 FROM deliveries WHERE event_id=? AND status IN ('sent','sending','uncertain')", (eid,)).fetchone()
                review = match['review']
                if changed and prior_sent and match['routes'] != json.dumps(rec['routes']):
                    review = 'После отправки изменилось отделение: проверить получателей.'
                db.execute('''UPDATE events SET rownum=?,name_key=?,surname=?,origin=?,routes=?,active=1,
                              stable=?,fingerprint=?,review=? WHERE id=?''',
                           (rec['row'], rec['name_key'], stored_surname, stored_origin,
                            json.dumps(rec['routes']), stable, fp, review, eid))
            event = db.execute('SELECT * FROM events WHERE id=?', (eid,)).fetchone()
            if (rec['date'], rec['section'], rec['row']) not in invalid:
                valid_ids.append(eid)
            for dest in DESTINATIONS:
                wanted = dest in rec['routes'] and not event['baseline'] and not expired
                if wanted:
                    db.execute("INSERT OR IGNORE INTO deliveries(event_id,destination,status) VALUES (?,?,'pending')", (eid, dest))
                    db.execute("UPDATE deliveries SET status='pending',note='' WHERE event_id=? AND destination=? AND status='cancelled'", (eid, dest))
                else:
                    db.execute("UPDATE deliveries SET status='cancelled',note='Строка не требует уведомления' WHERE event_id=? AND destination=? AND status IN ('pending','blocked')", (eid, dest))
        # Invalid rows are not treated as deleted; no send until they parse again.
        for event in old:
            if event['id'] not in used and (event['date'], event['section'], event['rownum']) in invalid:
                db.execute('UPDATE events SET active=1,stable=0 WHERE id=?', (event['id'],))
        db.execute("UPDATE deliveries SET status='cancelled',note='Строка удалена' WHERE status IN ('pending','blocked') AND event_id IN (SELECT id FROM events WHERE date LIKE ? AND active=0)", (month,))
        if baseline:
            set_meta(db, 'started_date', moment.date().isoformat())
            set_meta(db, 'initialized', '1')
    return valid_ids


class ApiFailure(Exception):
    def __init__(self, kind, note, retry_after=60):
        super().__init__(note)
        self.kind = kind
        self.note = note
        self.retry_after = retry_after


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None



def recover(db):
    # create is idempotent, and the exact ciphertext and ID are written before
    # HTTP. A crash at any point retries that same record, never a new message.
    with db:
        db.execute("UPDATE deliveries SET status='pending',note='Повторяю подтверждение той же записи' WHERE status='sending'")


def prune(db, moment):
    """Keep only keyed deduplication IDs after seven days, not patient names.

    This is logical removal plus SQLite secure_delete, not a claim to erase
    snapshots, storage-device wear-level copies, or old backups.
    """
    cutoff = cutoff_date(moment)
    with db:
        db.execute("UPDATE events SET surname='',origin='',review='' WHERE date<?", (cutoff,))
        db.execute("UPDATE deliveries SET status='cancelled',note='Истёк срок локальной очереди' WHERE status IN ('pending','blocked','sending') AND event_id IN (SELECT id FROM events WHERE date<?)", (cutoff,))
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='encrypted_outbox'").fetchone():
            db.execute("DELETE FROM encrypted_outbox WHERE delivery_id IN (SELECT d.id FROM deliveries d JOIN events e ON e.id=d.event_id WHERE e.date<?)", (cutoff,))


def dispatch(db, publisher, valid_ids, clock=now, should_stop=lambda: False):
    valid = set(valid_ids)
    sent = 0
    if clock().timestamp() < float(meta(db, 'retry_after', '0')):
        return 0
    rows = list(db.execute("""SELECT d.*,e.date,e.surname,e.section,e.stable,e.active,e.review,e.baseline,e.fingerprint
        FROM deliveries d JOIN events e ON e.id=d.event_id
        WHERE d.status='pending' ORDER BY e.date,e.id,d.id"""))
    for row in rows:
        moment = clock()
        if should_stop() or not in_window(moment):
            break
        if (row['event_id'] not in valid or not row['active'] or row['baseline'] or
                row['review'] or row['stable'] < 2 or row['date'] > moment.date().isoformat() or
                row['date'] < cutoff_date(moment) or not row['surname']):
            continue
        try:
            if publisher is None:
                raise ApiFailure('blocked', 'Шифрование не подключено. Открытые фамилии не отправляются.')
            # Prepare writes the exact ciphertext and random ID before any network
            # send. Authorization and recipient checks may take time; recheck 22:00.
            prepared = publisher.prepare(db, row, moment)
            if should_stop() or not in_window(clock()):
                break
            with db:
                db.execute("UPDATE deliveries SET status='sending',note='' WHERE id=?", (row['id'],))
            message_id = publisher.deliver(db, row, prepared)
        except ApiFailure as exc:
            status = 'blocked' if exc.kind == 'blocked' else 'pending'
            with db:
                db.execute('UPDATE deliveries SET status=?,note=? WHERE id=?', (status, exc.note, row['id']))
                if status == 'pending':
                    set_meta(db, 'retry_after', moment.timestamp() + exc.retry_after)
            break
        except Exception:
            with db:
                db.execute("UPDATE deliveries SET status='pending',note='Нет подтверждения. Повторю ту же зашифрованную запись.' WHERE id=?", (row['id'],))
                set_meta(db, 'retry_after', moment.timestamp() + 60)
            break
        else:
            with db:
                db.execute("UPDATE deliveries SET status='sent',message_id=?,note='Сохранено во входящих; это не подтверждает осмотр' WHERE id=?", (message_id, row['id']))
            sent += 1
    return sent
