"""Offline direct-delivery tests; invented records and local keys only."""
import ast
import datetime as dt
import hashlib
import io
import json
import os
import subprocess
import shutil
from pathlib import Path
import tempfile
import unittest
import urllib.error
from unittest import mock

import notifier as n
import pso_viewer as app
from team_crypto import OpenSSLIdentity, b64, compact, unb64
from team_publish import TeamClient, TeamFailure, TeamPublisher, verify_recipient, GRANT_DOMAIN, service_config, parse_invitation
from test_notifier import book, rec, moment

ENDPOINT, DIRECT_ENDPOINT, VIEWER = (service_config()[key] for key in ('team_endpoint', 'direct_endpoint', 'viewer_url'))


def viewer_docs():
    configured = os.environ.get('PSO_VIEWER_DOCS')
    if configured:
        return Path(configured).resolve()
    root = Path(__file__).resolve().parents[2]
    direct = root / 'docs'
    return direct if direct.is_dir() else root / 'github_viewer_release/docs'


class Response(io.BytesIO):
    def __init__(self, data):
        super().__init__(compact(data).encode())
        self.status = 200
        self.headers = {'Content-Type': 'application/json'}


class DeliveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        cls.identity = OpenSSLIdentity(Path(cls.keys.name) / 'sender', create=True)
        cls.recipient = OpenSSLIdentity(Path(cls.keys.name) / 'recipient', create=True)
        cls.organizer = OpenSSLIdentity(Path(cls.keys.name) / 'organizer', create=True)
        cls.member = {'id': cls.recipient.id, 'name': 'Врач тестовый', 'role': 'cardiologist', 'card': cls.recipient.card}

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'state.sqlite3'
        self.db = n.connect(self.path)
        n.ingest(self.db, book(), moment(), baseline=True)
        n.ingest(self.db, book([rec(section='orit')]), moment())
        self.valid = n.ingest(self.db, book([rec(section='orit')]), moment())
        self.team = mock.Mock()
        self.team.identity = self.identity
        self.team.organizer_card = self.organizer.card
        self.team.require_bot.return_value = None
        self.team.recipients.return_value = [self.member]
        self.team.create.side_effect = lambda data: {'id': data['id'], 'expires': data['expires'], 'push': 'queued'}
        self.publisher = TeamPublisher(self.db, self.team)

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def send(self, at=None):
        return n.dispatch(self.db, self.publisher, self.valid, clock=lambda: at or moment())

    def saved(self):
        return json.loads(self.db.execute('SELECT request FROM encrypted_outbox').fetchone()[0])

    def test_create_uses_ciphertext_and_marks_inbox_stored_without_pachca(self):
        self.assertEqual(self.send(), 1)
        data = self.saved()
        self.assertNotIn('Тестов', compact(data))
        self.assertEqual(data['kind'], 'admission')
        self.assertEqual(data['group'], 'cardiology')
        self.assertTrue(data['entries'][0]['token'].startswith('PSO1.'))
        self.assertEqual(data['expires'] - data['issued'], 172800000)
        self.assertEqual(data['organizerId'], self.organizer.id)
        self.assertTrue(data['organizerToken'].startswith('PSO1.' + self.organizer.id + '.' + self.identity.id + '.'))
        self.assertNotIn(self.organizer.id, [item['recipientId'] for item in data['entries']])
        self.assertEqual(self.db.execute('SELECT message_id FROM deliveries').fetchone()[0], data['id'])
        self.assertEqual(self.send(), 0)

    def assert_available_direction_sends_without_other_direction(self, available_role, available_group):
        records = book([rec(), rec('Пробов', row=14)])
        n.ingest(self.db, records, moment())
        self.valid = n.ingest(self.db, records, moment())
        at = int(moment().timestamp() * 1000)
        member = self.grant_member(issuer=self.organizer, at=at, role=available_role)
        directory = TeamClient(self.identity, clock=lambda: at, organizer_card=self.organizer.card)
        directory.request = mock.Mock(return_value={'members': [member]})
        self.team.recipients.side_effect = directory.recipients
        self.assertEqual(self.send(), 2)
        requests = [call[0][0] for call in self.team.create.call_args_list]
        self.assertEqual([data['group'] for data in requests], [available_group, available_group])
        self.assertEqual(len({data['id'] for data in requests}), 2)
        for data in requests:
            self.assertEqual([entry['recipientId'] for entry in data['entries']], [member['id']])
            self.assertTrue(data['entries'][0]['token'].startswith('PSO1.'))
            self.assertNotIn('Тестов', compact(data))
            self.assertNotIn('Пробов', compact(data))
        statuses = [tuple(row) for row in self.db.execute('''SELECT d.destination,d.status
            FROM deliveries d JOIN events e ON e.id=d.event_id WHERE e.active=1 ORDER BY d.id''')]
        available_destination = 'orit' if available_role == 'intensivist' else 'cardio'
        self.assertEqual(statuses, [(dest, 'sent' if dest == available_destination else 'blocked')
                                    for _ in range(2) for dest in ('cardio', 'orit')])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM encrypted_outbox').fetchone()[0], 2)
        self.assertEqual(self.send(), 0)
        self.assertEqual(self.team.create.call_count, 2)

    def test_missing_cardiologist_does_not_delay_any_intensivist_delivery(self):
        self.assert_available_direction_sends_without_other_direction('intensivist', 'orit')

    def test_missing_intensivist_does_not_delay_later_cardiology_deliveries(self):
        self.assert_available_direction_sends_without_other_direction('cardiologist', 'cardiology')

    def test_bot_authorization_failure_stops_before_all_recipient_checks(self):
        records = book([rec(), rec('Пробов', row=14)])
        n.ingest(self.db, records, moment())
        self.valid = n.ingest(self.db, records, moment())
        self.team.require_bot.side_effect = TeamFailure('blocked', 'Бот не активирован')
        self.assertEqual(self.send(), 0)
        self.assertEqual(self.team.require_bot.call_count, 1)
        self.team.recipients.assert_not_called()
        self.team.create.assert_not_called()
        statuses = [row[0] for row in self.db.execute('''SELECT d.status FROM deliveries d
            JOIN events e ON e.id=d.event_id WHERE e.active=1 ORDER BY d.id''')]
        self.assertEqual(statuses, ['blocked', 'pending', 'pending', 'pending'])

    def test_timeout_after_commit_retries_identical_record_after_restart(self):
        committed = {}
        calls = []
        def create(data):
            calls.append(compact(data))
            committed.setdefault(data['id'], compact(data))
            if len(calls) == 1:
                raise TeamFailure('retry', 'Потерян ответ')
            self.assertEqual(committed[data['id']], compact(data))
            return {'id': data['id'], 'expires': data['expires'], 'push': 'queued'}
        self.team.create.side_effect = create
        self.assertEqual(self.send(), 0)
        first = self.saved()
        self.db.close()
        self.db = n.connect(self.path)
        n.recover(self.db)
        self.publisher = TeamPublisher(self.db, self.team)
        self.assertEqual(self.send(moment(minute=2)), 1)
        self.assertEqual(self.saved(), first)
        self.assertEqual(len(committed), 1)
        self.assertEqual(calls[0], calls[1])

    def test_crash_after_server_commit_preserves_same_id(self):
        row = self.db.execute('SELECT d.*,e.fingerprint,e.section,e.surname FROM deliveries d JOIN events e ON e.id=d.event_id').fetchone()
        data = self.publisher.prepare(self.db, row, moment())
        with self.db:
            self.db.execute("UPDATE deliveries SET status='sending'")
        self.team.create(data)  # crash before local acknowledgement
        n.recover(self.db)
        self.assertEqual(self.send(), 1)
        self.assertEqual(self.team.create.call_args.args[0], data)

    def test_crossing_2200_after_encryption_never_begins_create(self):
        moments = iter([moment(hour=21, minute=59), moment(hour=21, minute=59), moment(hour=22)])
        self.assertEqual(n.dispatch(self.db, self.publisher, self.valid, clock=lambda: next(moments)), 0)
        self.team.create.assert_not_called()
        self.assertTrue(self.saved()['entries'])

    def test_revoked_or_unregistered_bot_blocks_plaintext_fallback(self):
        self.team.require_bot.side_effect = TeamFailure('blocked', 'Отозван')
        self.assertEqual(self.send(), 0)
        self.team.create.assert_not_called()
        self.assertEqual(self.db.execute('SELECT status FROM deliveries').fetchone()[0], 'blocked')

    def test_changed_report_after_uncertain_commit_does_not_send_old_surname(self):
        self.team.create.side_effect = TeamFailure('retry', 'Потерян ответ')
        self.send()
        n.ingest(self.db, book([rec('Другов', section='orit')]), moment(minute=2))
        self.valid = n.ingest(self.db, book([rec('Другов', section='orit')]), moment(minute=2))
        self.assertEqual(self.send(moment(minute=2)), 0)
        self.assertEqual(self.db.execute('SELECT status FROM deliveries').fetchone()[0], 'blocked')
        self.assertEqual(self.team.create.call_count, 1)

    def test_roster_change_before_commit_discards_stale_ciphertext(self):
        self.team.create.side_effect = TeamFailure('retry', 'Изменены получатели', 'roster_changed')
        self.assertEqual(self.send(), 0)
        self.assertEqual(self.db.execute('SELECT count(*) FROM encrypted_outbox').fetchone()[0], 0)

    def test_expired_ambiguous_create_never_generates_another_id_automatically(self):
        self.team.create.side_effect = TeamFailure('retry', 'Потерян ответ')
        self.send()
        before = self.saved()
        self.assertEqual(self.send(moment(day=16, minute=1)), 0)
        self.assertEqual(self.saved(), before)
        self.assertEqual(self.team.create.call_count, 1)
        self.assertEqual(self.db.execute('SELECT status FROM deliveries').fetchone()[0], 'blocked')

    def test_missing_pinned_organizer_blocks_before_any_outbox_or_send(self):
        self.team.organizer_card = ''
        self.assertEqual(self.send(), 0)
        self.team.create.assert_not_called()
        self.assertEqual(self.db.execute('SELECT count(*) FROM encrypted_outbox').fetchone()[0], 0)
        self.assertEqual(self.db.execute('SELECT status FROM deliveries').fetchone()[0], 'blocked')

    def test_existing_legacy_prepared_request_is_retried_without_reencryption_or_archive(self):
        self.team.create.side_effect = TeamFailure('retry', 'Потерян ответ')
        self.assertEqual(self.send(), 0)
        saved = self.saved()
        issued = saved['issued']
        old = {'id': saved['id'], 'group': 'cardiology', 'kind': 'admission',
               'issued': issued, 'expires': issued + 86400000,
               'entries': [{'recipientId': self.member['id'], 'token': self.identity.seal(
                   self.member, 'Тестов', 'ОРИТ', issued, issued + 86400000)}]}
        with self.db:
            self.db.execute('UPDATE encrypted_outbox SET request=?', (compact(old),))
        # An update must not replace an uncertain already-committed request,
        # even if the pinned organizer becomes unavailable before the retry.
        self.team.organizer_card = ''
        self.team.recipients.reset_mock()
        self.team.create.side_effect = lambda data: {'id': data['id'], 'expires': data['expires'], 'push': 'queued'}
        self.assertEqual(self.send(moment(minute=2)), 1)
        self.assertEqual(self.saved(), old)
        self.team.recipients.assert_not_called()
        self.assertNotIn('organizerToken', self.team.create.call_args.args[0])

    def test_bound_admission_copies_bind_same_message_group_and_expiry(self):
        self.assertEqual(self.send(), 1)
        data = self.saved()
        def decrypt(identity, token):
            parts = token.split('.')
            raw = identity.run(['pkeyutl', '-decrypt', '-inkey', str(identity.rsa_file),
                                '-pkeyopt', 'rsa_padding_mode:oaep', '-pkeyopt', 'rsa_oaep_md:sha256',
                                '-pkeyopt', 'rsa_mgf1_md:sha256',
                                '-pkeyopt', 'rsa_oaep_label:' + b'PSO-SURNAME-LINK-v1'.hex()], unb64(parts[3], 384))
            return json.loads(raw)
        received = decrypt(self.recipient, data['entries'][0]['token'])
        archived = decrypt(self.organizer, data['organizerToken'])
        self.assertEqual(received, archived)
        self.assertEqual(set(received), {'n', 'd', 'j', 'i', 'x', 'g'})
        self.assertEqual((received['j'], received['g'], received['i'], received['x']),
                         (data['id'], data['group'], data['issued'], data['expires']))
        with self.assertRaises(RuntimeError):
            decrypt(self.recipient, data['organizerToken'])

    def test_bound_seal_only_supports_exact_admission_groups_and_48_hours(self):
        issued, message_id = 1791961200000, b64(os.urandom(16))
        for args in [dict(message_id=message_id), dict(group='orit'),
                     dict(message_id='invalid', group='orit'), dict(message_id=message_id, group='rehab1')]:
            with self.assertRaises(ValueError):
                self.identity.seal(self.member, 'Тестов', 'ПСО', issued, issued + 60000, **args)
        for ttl in [59999, 172800001]:
            with self.assertRaises(ValueError):
                self.identity.seal(self.member, 'Тестов', 'ПСО', issued, issued + ttl,
                                   message_id=message_id, group='orit')
        with self.assertRaises(ValueError):
            self.identity.seal(self.member, 'Тестов', 'ПСО', issued, issued + 86400001)

    def test_retention_scrubs_names_and_reread_does_not_rehydrate(self):
        self.send()
        name_key = self.db.execute('SELECT name_key FROM events').fetchone()[0]
        self.assertNotEqual(name_key, 'тестов')
        n.prune(self.db, moment(day=23))
        n.ingest(self.db, book([rec(section='orit')]), moment(day=23))
        row = self.db.execute('SELECT surname,name_key,origin FROM events').fetchone()
        self.assertEqual(tuple(row), ('', name_key, ''))
        self.assertEqual(self.db.execute('SELECT count(*) FROM events').fetchone()[0], 1)
        self.assertEqual(self.db.execute('SELECT count(*) FROM encrypted_outbox').fetchone()[0], 0)
        self.assertEqual(self.send(moment(day=23)), 0)
        self.assertNotIn('Тестов'.encode(), self.path.read_bytes())

    def test_retention_cancels_unresolved_old_queue(self):
        n.prune(self.db, moment(day=23))
        self.assertEqual(self.db.execute('SELECT status FROM deliveries').fetchone()[0], 'cancelled')
        self.assertEqual(self.send(moment(day=23)), 0)

    def test_same_names_have_different_local_keys_in_independent_installations(self):
        other = n.connect(':memory:')
        try:
            self.assertNotEqual(n.identity_hash(self.db, 'тестов'), n.identity_hash(other, 'тестов'))
        finally:
            other.close()

    def test_network_requests_use_only_viewer_services_and_no_bearer_token(self):
        opener = mock.Mock()
        opener.open.side_effect = [Response({'state':'active','role':'bot','name':'Бот'}), Response({'id':'record','expires':123}), Response({'pending':0})]
        client = TeamClient(self.identity, opener=opener, clock=lambda: 1791961200000)
        client.require_bot()
        client.create({'id':'record','expires':123})
        client.retry_notifications()
        reqs = [call.args[0] for call in opener.open.call_args_list]
        self.assertEqual([r.full_url for r in reqs], [ENDPOINT,DIRECT_ENDPOINT,DIRECT_ENDPOINT])
        self.assertEqual([json.loads(r.data)['envelope']['op'] for r in reqs], ['status','create','retry'])
        for request in reqs:
            self.assertNotIn('Authorization', request.headers)
            self.assertNotIn('pachca', request.full_url)
            self.assertNotIn('Тестов'.encode(), request.data)

    def test_server_errors_do_not_print_response_or_patient_content(self):
        opener = mock.Mock()
        opener.open.side_effect = urllib.error.HTTPError(DIRECT_ENDPOINT, 500, 'server', {}, io.BytesIO(b'patient private secret'))
        with self.assertRaises(TeamFailure) as cm:
            TeamClient(self.identity, opener=opener).request('retry', {}, direct=True)
        self.assertNotIn('private', str(cm.exception))

    def test_archive_errors_are_explicit_and_keep_same_encrypted_retry(self):
        for status, code, note in [(429, 'history_full', 'Архив сообщений заполнен'),
                                   (503, 'history_unavailable', 'Сначала обновите pso-api')]:
            opener = mock.Mock()
            opener.open.side_effect = urllib.error.HTTPError(DIRECT_ENDPOINT, status, 'server', {},
                io.BytesIO(compact({'error': code, 'private': 'patient secret'}).encode('utf-8')))
            with self.assertRaises(TeamFailure) as cm:
                TeamClient(self.identity, opener=opener).request('create', {}, direct=True)
            self.assertEqual(cm.exception.kind, 'retry')
            self.assertEqual(cm.exception.code, code)
            self.assertIn(note, str(cm.exception))
            self.assertNotIn('secret', str(cm.exception))

    def test_sources_config_import_reads_no_token_or_queue(self):
        old = Path(self.temp.name) / 'old'
        old.mkdir()
        (old / 'token.txt').write_text('NEVERREAD')
        config = {'sources': {'2026-10':'/synthetic/10.xlsx'},'folder':'/synthetic','anchor_year':2026,'anchor_month':10,'token':'NEVERREAD'}
        (old / 'config.json').write_text(json.dumps(config))
        before = (old / 'config.json').read_bytes()
        with mock.patch.object(app, 'OLD_DATA', old):
            imported = app.imported_config()
        self.assertEqual(set(imported), {'sources','folder','anchor_year','anchor_month'})
        self.assertNotIn('NEVERREAD', compact(imported))
        self.assertEqual(before, (old / 'config.json').read_bytes())

    def test_identity_and_autostart_are_independent_of_old_bot(self):
        self.assertEqual(app.DATA.name, 'pso-viewer-bot')
        self.assertEqual(app.OLD_DATA.name, 'pso-pachca')
        with mock.patch.object(app, 'config'), mock.patch.object(app.Path, 'home', return_value=Path(self.temp.name)):
            app.autostart()
        target = Path(self.temp.name) / '.config/autostart/pso-viewer-bot.desktop'
        self.assertTrue(target.is_file())
        self.assertIn('pso_viewer.py', target.read_text())
        self.assertNotIn('pso_pachca.py', target.read_text())

    def test_webcrypto_opens_python_openssl_tokens(self):
        module = viewer_docs() / 'exchange.mjs'
        if not module.is_file() or not shutil.which('node'):
            self.skipTest('Node and viewer source required for cross-runtime test')
        env = dict(os.environ, PSO_EXCHANGE_MODULE=module.as_uri())
        process = subprocess.Popen(['node', str(Path(__file__).with_name('test_interop.mjs'))], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        try:
            from team_crypto import read_card
            cards = json.loads(process.stdout.readline())['cards']
            recipients = [read_card(c) for c in cards]
            now_ms = 1791961200000
            tokens = [self.identity.seal(c, 'Тестов-Пробный', 'ОРИТ', now_ms, now_ms + 3600000) for c in recipients]
            envelope = self.identity.envelope('status', {}, now_ms)
            output, errors = process.communicate(compact({'card':self.identity.card,'tokens':tokens,'envelope':envelope,'now':now_ms}) + '\n', timeout=45)
            self.assertEqual(process.returncode,0,errors)
            result=json.loads(output)
            self.assertEqual(result['first']['surname'],'Тестов-Пробный')
            self.assertEqual(result['second']['department'],'ОРИТ')
            self.assertTrue(result['wrong'])
            self.assertTrue(result['tampered'])
            self.assertTrue(result['verified'])
        finally:
            if process.poll() is None:
                process.kill();process.communicate()

    def test_bound_admission_and_organizer_archive_interoperate_with_browser(self):
        module = viewer_docs() / 'exchange.mjs'
        if not module.is_file() or not shutil.which('node'):
            self.skipTest('Node and viewer source required for cross-runtime test')
        env = dict(os.environ, PSO_EXCHANGE_MODULE=module.as_uri())
        process = subprocess.Popen(['node', str(Path(__file__).with_name('test_history_interop.mjs'))],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, env=env)
        try:
            from team_crypto import read_card
            cards = [read_card(c) for c in json.loads(process.stdout.readline())['cards']]
            now_ms, message_id = 1791961200000, b64(os.urandom(16))
            meta = {'id': message_id, 'group': 'cardiology', 'kind': 'admission',
                    'issued': now_ms, 'expires': now_ms + 172800000}
            seal = lambda card, mid: self.identity.seal(card, 'Тестов-Пробный', 'ОРИТ', now_ms,
                meta['expires'], message_id=mid, group=meta['group'])
            request = {'botCard': self.identity.card, 'meta': meta,
                       'recipientToken': seal(cards[0], message_id),
                       'organizerToken': seal(cards[1], message_id),
                       'organizerOtherToken': seal(cards[1], b64(os.urandom(16))),
                       'unboundToken': self.identity.seal(cards[1], 'Тестов-Пробный', 'ОРИТ', now_ms, now_ms + 86400000)}
            output, errors = process.communicate(compact(request) + '\n', timeout=45)
            self.assertEqual(process.returncode, 0, errors)
            result = json.loads(output)
            for key in ('first', 'late', 'archive', 'last'):
                self.assertEqual(result[key]['surname'], 'Тестов-Пробный')
                self.assertEqual(result[key]['messageId'], message_id)
                self.assertEqual(result[key]['group'], 'cardiology')
            for key in ('expired', 'archiveExpired', 'wrongRecipient', 'wrongOrganizer',
                        'substitutedID', 'substitutedGroup', 'unboundRejected'):
                self.assertTrue(result[key], key)
        finally:
            if process.poll() is None:
                process.kill();process.communicate()

    def grant_member(self, issuer=None, at=1791961200000, role='cardiologist'):
        issuer = issuer or self.identity
        grant = {'v':1,'subjectId':self.member['id'],'role':role,'name':self.member['name'],
                 'issued':at,'expires':at+86400000,'issuerId':issuer.id}
        proof = {'grant':grant,'signature':b64(issuer.sign((GRANT_DOMAIN+compact(grant)).encode('utf-8'))),
                 'issuerCard':issuer.card}
        return dict(self.member, role=role, approvalProof=proof)

    def test_pinned_organizer_signature_accepts_exact_recipient(self):
        at=1791961200000
        member=self.grant_member(at=at)
        verified=verify_recipient(member,self.identity.card,self.identity,at)
        self.assertEqual(verified['id'],self.member['id'])

    def test_cloud_cannot_replace_organizer_or_approved_key_role_name(self):
        at=1791961200000
        for member in [self.grant_member(issuer=self.recipient),
                       dict(self.grant_member(),name='Другое имя'),
                       dict(self.grant_member(),role='intensivist'),
                       dict(self.grant_member(),id=self.identity.id,card=self.identity.card)]:
            with self.assertRaises((ValueError,RuntimeError)):
                verify_recipient(member,self.identity.card,self.identity,at)
        with self.assertRaises(ValueError):
            verify_recipient(self.grant_member(),'',self.identity,at)

    def test_tampered_expired_or_extra_field_approval_denied(self):
        at=1791961200000
        for mutate in [lambda m:m['approvalProof']['grant'].update(expires=at),
                       lambda m:m['approvalProof']['grant'].update(name='Подменено'),
                       lambda m:m['approvalProof']['grant'].update(extra='unexpected'),
                       lambda m:m['approvalProof'].update(signature=b64(b'x'*64))]:
            member=self.grant_member(at=at)
            mutate(member)
            with self.assertRaises((ValueError,RuntimeError)):
                verify_recipient(member,self.identity.card,self.identity,at)

    def test_directory_signature_pinning_is_mandatory_and_uses_direct_endpoint(self):
        at=1791961200000
        member=self.grant_member(at=at)
        client=TeamClient(self.identity,clock=lambda:at,organizer_card=self.identity.card)
        client.request=mock.Mock(return_value={'members':[member]})
        self.assertEqual(client.recipients('cardio'),[member])
        client.request.assert_called_with('directory',{},direct=True)
        client.organizer_card=''
        with self.assertRaises(TeamFailure):client.recipients('cardio')

    def test_only_valid_directory_without_matching_role_reports_no_recipients(self):
        at = 1791961200000
        client = TeamClient(self.identity, clock=lambda: at, organizer_card=self.identity.card)
        member = self.grant_member(at=at, role='intensivist')
        client.request = mock.Mock(return_value={'members': [member]})
        with self.assertRaises(TeamFailure) as missing:
            client.recipients('cardio')
        self.assertEqual((missing.exception.kind, missing.exception.code), ('blocked', 'no_recipients'))
        for invalid in [{'members': []}, {'members': 'invalid'},
                        {'members': [dict(member, role='unknown')]},
                        {'members': [dict(member, card='invalid')]},
                        {'members': [member, member]},
                        {'members': [dict(member, role='cardiologist')]}]:
            with self.subTest(directory=invalid):
                client.request.return_value = invalid
                with self.assertRaises(TeamFailure) as failure:
                    client.recipients('cardio')
                self.assertEqual(failure.exception.kind, 'blocked')
                self.assertNotEqual(failure.exception.code, 'no_recipients')

    def test_invitation_carries_pinned_organizer_without_server_lookup(self):
        from urllib.parse import urlencode
        join=b64(os.urandom(16))
        url=VIEWER+'#'+urlencode({'join':join,'organizer':self.identity.card})
        self.assertEqual(app.activation_details(url),(join,self.identity.card))
        with mock.patch.object(app,'DATA',Path(self.temp.name)),mock.patch('builtins.input',return_value='д'):
            app.pin_organizer(self.identity.card)
            with self.assertRaises(RuntimeError):app.pin_organizer(self.recipient.card)
        self.assertEqual((Path(self.temp.name)/'organizer.card').read_text().strip(),self.identity.card)

    def test_python_openssl_verifies_browser_created_organizer_grant(self):
        base=viewer_docs()
        if not (base/'recipient-trust.mjs').is_file() or not shutil.which('node'):
            self.skipTest('Node and viewer certificate source required')
        process=subprocess.run(['node',str(Path(__file__).with_name('test_grant_interop.mjs'))],
            env=dict(os.environ,PSO_VIEWER_BASE=base.as_uri()+'/'),capture_output=True,text=True,timeout=45)
        self.assertEqual(process.returncode,0,process.stderr)
        fixture=json.loads(process.stdout)
        card=verify_recipient(fixture['member'],fixture['organizerCard'],self.identity,fixture['now'])
        self.assertEqual(card['id'],fixture['member']['id'])
        client=TeamClient(self.identity,clock=lambda:fixture['now'],organizer_card='')
        client.services=dict(client.services,viewer_url='https://viewer.example/')
        client.request=mock.Mock(return_value={'id':fixture['invitationId'],'expires':fixture['now']+60000,'organizerCard':fixture['organizerCard']})
        self.assertEqual(client.resolve_invitation(fixture['invitationURL']),(fixture['invitationId'],fixture['organizerCard']))

    def short_invitation(self, card=None):
        card = card or self.identity.card
        raw_id = os.urandom(16)
        return (VIEWER + '#i=' + b64(raw_id + hashlib.sha256(card.encode('utf-8')).digest()), b64(raw_id))

    def test_short_invitation_matches_hash_and_uses_readonly_signed_team_lookup(self):
        at = 1791961200000
        link, invitation_id = self.short_invitation()
        opener = mock.Mock()
        opener.open.return_value = Response({'id': invitation_id, 'expires': at + 60000, 'organizerCard': self.identity.card})
        client = TeamClient(self.recipient, opener=opener, clock=lambda: at, organizer_card='')
        self.assertEqual(client.resolve_invitation(link), (invitation_id, self.identity.card))
        request = opener.open.call_args[0][0]
        envelope = json.loads(request.data.decode('utf-8'))['envelope']
        self.assertEqual(request.full_url, ENDPOINT)
        self.assertEqual(envelope['op'], 'invite_info')
        self.assertEqual(envelope['data'], {'id': invitation_id})
        self.assertNotIn('organizerHash', compact(envelope))
        self.assertEqual(client.organizer_card, '')
        self.assertFalse((self.recipient.directory.parent / 'organizer.card').exists())
        self.assertEqual(opener.open.call_count, 1)

    def test_short_invitation_rejects_replaced_key_id_expiry_and_extra_fields(self):
        at = 1791961200000
        link, invitation_id = self.short_invitation()
        client = TeamClient(self.recipient, clock=lambda: at, organizer_card='')
        good = {'id': invitation_id, 'expires': at + 60000, 'organizerCard': self.identity.card}
        for patch in ({'organizerCard': self.recipient.card}, {'id': b64(os.urandom(16))},
                      {'expires': at}, {'expires': True}, {'expires': 9007199254740992},
                      {'organizerCard': 'broken'}, {'unexpected': 'value'}):
            client.request = mock.Mock(return_value=dict(good, **patch))
            with self.assertRaises(TeamFailure):
                client.resolve_invitation(link)
            client.request.assert_called_once_with('invite_info', {'id': invitation_id})

    def test_short_invitation_refuses_wrong_host_path_query_and_truncated_tokens_before_network(self):
        link, invitation_id = self.short_invitation()
        client = TeamClient(self.recipient, organizer_card='')
        client.request = mock.Mock()
        token = link.split('#i=', 1)[1]
        for invalid in (link.replace(VIEWER, 'https://other.example/'), VIEWER + 'extra/#i=' + token,
                        VIEWER + '?tracking=1#i=' + token, link[:-1], link + '&i=' + token,
                        VIEWER + '#i=' + token + '&join=' + invitation_id,
                        VIEWER + '#i=%' + format(ord(token[0]), '02X') + token[1:],
                        VIEWER + '#m=' + invitation_id):
            with self.assertRaises(ValueError):
                client.resolve_invitation(invalid)
        client.request.assert_not_called()

    def test_old_invitation_formats_remain_local_and_match_configured_viewer(self):
        from urllib.parse import urlencode
        join = b64(os.urandom(16))
        client = TeamClient(self.recipient, organizer_card='')
        client.request = mock.Mock()
        legacy = VIEWER + '#' + urlencode({'join': join, 'organizer': self.identity.card})
        packed = VIEWER + '#invite=' + b64(compact({'v': 1, 'id': join, 'organizer': self.identity.card}).encode('utf-8'))
        for link in (legacy, packed):
            self.assertEqual(client.resolve_invitation(link), (join, self.identity.card))
        self.assertEqual(client.resolve_invitation(join), (join, ''))
        self.assertEqual(client.resolve_invitation(VIEWER + '#join=' + join), (join, ''))
        client.request.assert_not_called()

    def test_short_invitation_enrollment_keeps_explicit_confirmation_before_claim(self):
        link, join = self.short_invitation(self.recipient.card)
        client = mock.Mock()
        client.resolve_invitation.return_value = (join, self.recipient.card)
        client.claim.return_value = {'state': 'pending'}
        fake_identity = mock.Mock(id=self.identity.id)
        fake_identity.run.return_value = b'OpenSSL synthetic test'
        data = Path(self.temp.name)
        with mock.patch.object(app, 'DATA', data), mock.patch.object(app, 'OpenSSLIdentity', return_value=fake_identity), \
                mock.patch.object(app, 'TeamClient', return_value=client), mock.patch('builtins.print'), \
                mock.patch('builtins.input', side_effect=[link, 'нет']):
            with self.assertRaises(RuntimeError):
                app.setup_encryption()
        client.claim.assert_not_called()
        self.assertFalse((data / 'organizer.card').exists())
        with mock.patch.object(app, 'DATA', data), mock.patch.object(app, 'OpenSSLIdentity', return_value=fake_identity), \
                mock.patch.object(app, 'TeamClient', return_value=client), mock.patch('builtins.print'), \
                mock.patch('builtins.input', side_effect=[link, 'д']):
            app.setup_encryption()
        client.claim.assert_called_once_with(join)
        self.assertEqual((data / 'organizer.card').read_text().strip(), self.recipient.card)

    def test_missing_or_invalid_service_config_never_uses_old_host(self):
        for error in (OSError('missing'), ValueError('invalid')):
            fake = mock.Mock()
            fake.with_name.return_value.read_text.side_effect = error
            with mock.patch('team_publish.Path', return_value=fake), self.assertRaises(RuntimeError):
                service_config()

    def test_service_configuration_requires_https_without_credentials_or_redirects(self):
        valid={'team_endpoint':'https://medical.example/api/team','direct_endpoint':'https://medical.example/api/direct','viewer_url':'https://viewer.medical.example/'}
        for bad in ['http://medical.example/api','https://user:pass@medical.example/api','https://medical.example/api?secret=x','https://medical.example/api#x']:
            data=dict(valid,direct_endpoint=bad)
            fake=mock.Mock()
            fake.with_name.return_value.exists.return_value=True
            fake.with_name.return_value.read_text.return_value=json.dumps(data)
            with mock.patch('team_publish.Path',return_value=fake),self.assertRaises(RuntimeError):service_config()

    def test_relocation_configuration_changes_only_public_addresses_and_origin(self):
        cfg={'team_endpoint':'https://medical.example/api/team','direct_endpoint':'https://medical.example/api/direct','viewer_url':'https://viewer.medical.example/'}
        with mock.patch('team_publish.service_config',return_value=cfg):
            opener=mock.Mock()
            opener.open.return_value=Response({'pending':0})
            client=TeamClient(self.identity,opener=opener,organizer_card=self.identity.card)
            client.retry_notifications()
            request=opener.open.call_args.args[0]
        self.assertEqual(request.full_url,cfg['direct_endpoint'])
        self.assertEqual(request.headers['Origin'],'https://viewer.medical.example')
        self.assertEqual(client.organizer_card,self.identity.card)

    def test_sources_are_python37_and_no_pachca_transport_implementation_exists(self):
        root = Path(__file__).parent
        for filename in ('notifier.py','pso_viewer.py','team_publish.py','team_crypto.py','xlsx_reader.py'):
            source = (root / filename).read_text()
            ast.parse(source, feature_version=(3,7))
            self.assertNotIn('api.pachca.com', source)
            self.assertNotIn('class Pachca', source)
            self.assertNotIn('Bearer ', source)


if __name__ == '__main__':
    unittest.main()
