"""Encrypted, idempotent viewer delivery. No Pachca API is used."""
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlparse
import unicodedata
import time
import urllib.error
import urllib.request

from notifier import ApiFailure, NoRedirect
from team_crypto import OpenSSLIdentity, b64, compact, read_card, unb64

ENDPOINT = 'https://spugfikalpihorcwcdqc.supabase.co/functions/v1/pso-team'
DIRECT_ENDPOINT = 'https://spugfikalpihorcwcdqc.supabase.co/functions/v1/pso-direct'
VIEWER = 'https://evgk724.github.io/pso-code-viewer/'
ORIGIN = 'https://evgk724.github.io'
GRANT_DOMAIN = 'PSO-RECIPIENT-GRANT-v1\0'
MAX_GRANT_TTL = 365 * 86400000
GROUPS = {'cardio': ('cardiology', 'cardiologist'), 'orit': ('orit', 'intensivist')}


def service_config():
    path = Path(__file__).with_name('service-config.json')
    default = {'team_endpoint': ENDPOINT, 'direct_endpoint': DIRECT_ENDPOINT, 'viewer_url': VIEWER}
    try:
        data = json.loads(path.read_text(encoding='utf-8')) if path.exists() else default
    except (OSError, ValueError):
        raise RuntimeError('Не удалось прочитать service-config.json. Сообщения не отправляются.') from None
    if not isinstance(data, dict) or set(data) != set(default):
        raise RuntimeError('Неверный формат адресов service-config.json.')
    for key, value in data.items():
        if not isinstance(value, str) or any(c.isspace() for c in value):
            raise RuntimeError('Некорректный адрес сервиса.')
        parsed = urlparse(value)
        if parsed.scheme != 'https' or not parsed.netloc or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.params:
            raise RuntimeError('Адреса просмотрщика и сервисов должны быть HTTPS без пароля, параметров и фрагмента.')
        try:
            parsed.port
        except ValueError:
            raise RuntimeError('Некорректный порт сервиса.') from None
    if not data['viewer_url'].endswith('/'):
        raise RuntimeError('Адрес просмотрщика должен завершаться символом /.')
    return data


def source_digest(row):
    return hashlib.sha256(compact([row['fingerprint'], row['destination'], row['section']]).encode('utf-8')).hexdigest()


def verify_recipient(member, organizer_card, identity, at):
    """An untrusted directory cannot silently substitute a recipient public key."""
    if not organizer_card:
        raise ValueError('Не закреплён ключ организатора. Повторите подключение по его приглашению.')
    root = read_card(organizer_card)
    card = read_card(member.get('card'))
    proof = member.get('approvalProof')
    if not isinstance(proof, dict) or set(proof) != {'grant', 'signature', 'issuerCard'}:
        raise ValueError('Организатор ещё не подтвердил ключ получателя.')
    issuer = read_card(proof['issuerCard'])
    grant = proof['grant']
    fields = ('v', 'subjectId', 'role', 'name', 'issued', 'expires', 'issuerId')
    if not isinstance(grant, dict) or set(grant) != set(fields):
        raise ValueError('Некорректное подтверждение получателя.')
    issued, expires = grant['issued'], grant['expires']
    name = grant['name']
    if (isinstance(at, bool) or not isinstance(at, int) or not 0 < at <= 9007199254740991 or
            grant['v'] != 1 or isinstance(grant['v'], bool) or issuer['id'] != root['id'] or
            grant['role'] not in ('admin', 'neurologist', 'cardiologist', 'intensivist', 'bot') or
            (grant['role'] == 'admin' and grant['subjectId'] != grant['issuerId']) or
            grant['issuerId'] != root['id'] or card['id'] != member.get('id') or
            grant['subjectId'] != card['id'] or grant['role'] != member.get('role') or
            grant['name'] != member.get('name') or
            not isinstance(name, str) or name != unicodedata.normalize('NFC', name).strip() or
            not 1 <= len(name) <= 60 or any(unicodedata.category(c) in ('Cc', 'Cf') for c in name) or
            isinstance(issued, bool) or not isinstance(issued, int) or
            isinstance(expires, bool) or not isinstance(expires, int) or
            not 0 < issued <= at + 30000 or not at < expires <= 9007199254740991 or
            not 0 < expires - issued <= MAX_GRANT_TTL):
        raise ValueError('Подтверждение получателя не совпало с закреплённым ключом организатора.')
    canonical = {key: grant[key] for key in fields}
    identity.verify_signature(root['ec'], unb64(proof['signature'], 64), (GRANT_DOMAIN + compact(canonical)).encode('utf-8'))
    return card


class TeamFailure(RuntimeError):
    def __init__(self, kind, note, code=''):
        super().__init__(note)
        self.kind, self.note, self.code = kind, note, code


class TeamClient:
    def __init__(self, identity, opener=None, clock=None, organizer_card=None):
        self.identity = identity
        self.services = service_config()
        viewer = urlparse(self.services['viewer_url'])
        self.origin = viewer.scheme + '://' + viewer.netloc
        if organizer_card is None:
            try:
                organizer_card = (identity.directory.parent / 'organizer.card').read_text(encoding='utf-8').strip()
            except OSError:
                organizer_card = ''
        self.organizer_card = organizer_card
        self.opener = opener or urllib.request.build_opener(NoRedirect())
        self.clock = clock or (lambda: int(time.time() * 1000))

    def request(self, op, data, direct=False):
        body = compact({'envelope': self.identity.envelope(op, data, self.clock())}).encode('utf-8')
        request = urllib.request.Request(self.services['direct_endpoint' if direct else 'team_endpoint'], data=body, method='POST', headers={
            'Content-Type': 'application/json', 'Accept': 'application/json',
            'Origin': self.origin})
        try:
            with self.opener.open(request, timeout=20) as response:
                raw = response.read(256 * 1024 + 1)
                if response.status != 200 or len(raw) > 256 * 1024 or not response.headers.get('Content-Type', '').startswith('application/json'):
                    raise ValueError('bad response')
                result = json.loads(raw.decode('utf-8'))
                if not isinstance(result, dict):
                    raise ValueError('bad response')
                return result
        except urllib.error.HTTPError as exc:
            code = ''
            try:
                raw = exc.read(2048)
                obj = json.loads(raw.decode('utf-8'))
                if isinstance(obj, dict) and obj.get('error') in ('roster_changed', 'id_conflict', 'replay', 'expired'):
                    code = obj['error']
            except Exception:
                pass
            if exc.code == 409 and code == 'roster_changed':
                raise TeamFailure('retry', 'Состав получателей изменился; список будет обновлён.', code)
            if exc.code == 429 or exc.code >= 500 or (exc.code == 409 and code == 'replay'):
                raise TeamFailure('retry', 'Сервис шифрованных ссылок временно недоступен. Повтор с тем же кодом через минуту.', code)
            raise TeamFailure('blocked', 'Сервис не разрешил отправку. Проверьте активацию бота и получателей.', code)
        except TeamFailure:
            raise
        except Exception:
            raise TeamFailure('retry', 'Нет подтверждения сервиса ссылок. Сохранённый код будет проверен повторно.') from None

    def status(self):
        value = self.request('status', {})
        if value.get('state') not in ('unregistered', 'pending', 'active', 'revoked') or value.get('role') not in (None, 'admin', 'neurologist', 'cardiologist', 'intensivist', 'bot'):
            raise TeamFailure('blocked', 'Сервис вернул неизвестное состояние устройства.')
        return value

    def require_bot(self):
        value = self.status()
        if value['state'] != 'active' or value.get('role') != 'bot':
            raise TeamFailure('blocked', 'Бот ещё не активирован администратором. Откройте пункт «Подключить шифрование».')

    def claim(self, invite):
        unb64(invite, 16)
        value = self.request('claim', {'id': invite})
        if value.get('state') not in ('pending', 'active'):
            raise TeamFailure('blocked', 'Активация не подтверждена сервисом.')
        return value

    def recipients(self, destination):
        value = self.request('directory', {}, direct=True)
        members = value.get('members')
        if not isinstance(members, list) or not 1 <= len(members) <= 100:
            raise TeamFailure('blocked', 'Не удалось получить список активированных врачей.')
        role = GROUPS[destination][1]
        selected, seen = [], set()
        for member in members:
            if not isinstance(member, dict) or member.get('role') not in ('admin', 'neurologist', 'cardiologist', 'intensivist', 'bot'):
                raise TeamFailure('blocked', 'Не удалось проверить роли получателей.')
            try:
                card = read_card(member.get('card'))
                if card['id'] != member.get('id') or card['id'] in seen:
                    raise ValueError('identity')
                seen.add(card['id'])
            except (ValueError, TypeError, UnicodeError):
                raise TeamFailure('blocked', 'Не удалось проверить ключи получателей.') from None
            if member['role'] == role:
                try:
                    verify_recipient(member, self.organizer_card, self.identity, self.clock())
                except (ValueError, TypeError, RuntimeError):
                    raise TeamFailure('blocked', 'Ключ получателя не подтверждён вашим организатором. Проверьте раздел «Команда» и закреплённый ключ бота.') from None
                selected.append(member)
        if not selected:
            raise TeamFailure('blocked', 'Для этого чата ещё нет активированных получателей.')
        return sorted(selected, key=lambda m: m['id'])

    def create(self, data):
        value = self.request('create', data, direct=True)
        if value.get('id') != data['id'] or value.get('expires') != data['expires']:
            raise TeamFailure('retry', 'Ответ сервиса ссылок не подтверждён. Сохранённый код будет проверен повторно.')
        return value

    def retry_notifications(self):
        result = self.request('retry', {}, direct=True)
        return result


class TeamPublisher:
    def __init__(self, db, team):
        self.team = team
        with db:
            db.execute('''CREATE TABLE IF NOT EXISTS encrypted_outbox (
              delivery_id INTEGER PRIMARY KEY REFERENCES deliveries(id),
              source_hash TEXT NOT NULL, request TEXT NOT NULL,
              accepted INTEGER NOT NULL DEFAULT 0)''')

    def prepare(self, db, row, moment):
        source_hash = source_digest(row)
        saved = db.execute('SELECT * FROM encrypted_outbox WHERE delivery_id=?', (row['id'],)).fetchone()
        try:
            self.team.require_bot()
            if saved:
                if saved['source_hash'] != source_hash:
                    raise TeamFailure('blocked', 'Запись изменена после подготовки. Откройте «Разобрать вопросы»; прежняя запись могла уже попасть во входящие.')
                data = json.loads(saved['request'])
            else:
                recipients = self.team.recipients(row['destination'])
                issued = int(moment.timestamp() * 1000)
                expires = issued + 86400000
                department = 'ОРИТ' if row['section'] == 'orit' else 'ПСО'
                entries = [{'recipientId': member['id'], 'token': self.team.identity.seal(member, row['surname'], department, issued, expires)} for member in recipients]
                data = {'id': b64(os.urandom(16)), 'group': GROUPS[row['destination']][0],
                        'kind': 'admission', 'issued': issued, 'expires': expires, 'entries': entries}
                with db:
                    db.execute('INSERT INTO encrypted_outbox(delivery_id,source_hash,request) VALUES (?,?,?)',
                               (row['id'], source_hash, compact(data)))
            if data['expires'] <= int(moment.timestamp() * 1000):
                raise TeamFailure('blocked', 'Истёк срок подготовленной записи. Требуется проверить очередь; новая запись автоматически не создаётся.')
            return data
        except TeamFailure as exc:
            raise ApiFailure(exc.kind, exc.note) from None
        except (OSError, ValueError, RuntimeError):
            raise ApiFailure('blocked', 'Не удалось зашифровать запись. Открытая фамилия не отправлена.') from None

    def deliver(self, db, row, data):
        try:
            # The exact same ID and ciphertext are retried after lost responses.
            # No separate chat operation follows this commit.
            self.team.create(data)
            with db:
                db.execute('UPDATE encrypted_outbox SET accepted=1 WHERE delivery_id=?', (row['id'],))
            return data['id']
        except TeamFailure as exc:
            if exc.code == 'roster_changed':
                saved = db.execute('SELECT accepted FROM encrypted_outbox WHERE delivery_id=?', (row['id'],)).fetchone()
                if saved and not saved['accepted']:
                    # The broker only emits roster_changed before committing.
                    with db:
                        db.execute('DELETE FROM encrypted_outbox WHERE delivery_id=?', (row['id'],))
            raise ApiFailure(exc.kind, exc.note) from None


def reset_prepared_after_review(db, delivery_id):
    row = db.execute("SELECT d.*,e.active,e.baseline,e.review FROM deliveries d JOIN events e ON e.id=d.event_id WHERE d.id=?", (delivery_id,)).fetchone()
    if not row or row['status'] != 'blocked' or row['message_id'] or not row['active'] or row['baseline'] or row['review']:
        raise RuntimeError('Эта доставка не может быть подготовлена заново.')
    with db:
        db.execute('DELETE FROM encrypted_outbox WHERE delivery_id=?', (delivery_id,))
        db.execute("UPDATE deliveries SET status='pending',note='Организатор проверил очередь и разрешил новую запись' WHERE id=?", (delivery_id,))
