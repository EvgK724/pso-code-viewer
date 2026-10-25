"""Offline direct-delivery tests; invented records and local keys only."""
import ast
import datetime as dt
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
from team_crypto import OpenSSLIdentity, b64, compact
from team_publish import TeamClient, TeamFailure, TeamPublisher, ENDPOINT, DIRECT_ENDPOINT, VIEWER, verify_recipient, GRANT_DOMAIN, service_config
from test_notifier import book, rec, moment


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
        self.assertEqual(self.db.execute('SELECT message_id FROM deliveries').fetchone()[0], data['id'])
        self.assertEqual(self.send(), 0)

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
        self.assertEqual(self.send(moment(day=15, minute=1)), 0)
        self.assertEqual(self.saved(), before)
        self.assertEqual(self.team.create.call_count, 1)
        self.assertEqual(self.db.execute('SELECT status FROM deliveries').fetchone()[0], 'blocked')

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

    def grant_member(self, issuer=None, at=1791961200000):
        issuer = issuer or self.identity
        grant = {'v':1,'subjectId':self.member['id'],'role':'cardiologist','name':self.member['name'],
                 'issued':at,'expires':at+86400000,'issuerId':issuer.id}
        proof = {'grant':grant,'signature':b64(issuer.sign((GRANT_DOMAIN+compact(grant)).encode('utf-8'))),
                 'issuerCard':issuer.card}
        return dict(self.member, approvalProof=proof)

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
