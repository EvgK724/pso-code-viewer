"""Offline reliability tests. All names and API responses are synthetic."""
import datetime as dt
import os
import tempfile
import unittest
import hashlib
import base64
from unittest import mock

import notifier as n


def moment(day=14, hour=12, minute=0, month=10):
    return dt.datetime(2026, month, day, hour, minute, tzinfo=n.LOCAL_TZ)


def rec(name='Тестов', row=13, section='pso', date='2026-10-14',
        routes=None, origin=''):
    if routes is None:
        routes = ['cardio', 'orit'] if section == 'pso' else ['cardio']
    return dict(date=date, section=section, row=row, name_key=name.casefold(),
                surname=name, origin=origin, routes=routes)


def book(records=(), month=10, issues=()):
    return dict(year=2026, month=month, records=list(records), issues=list(issues))


def sealed_message(name, orit=False):
    code = base64.urlsafe_b64encode(hashlib.sha256(name.encode('utf-8')).digest()[:16]).decode().rstrip('=')
    return ('Новый пациент ОРИТ' if orit else 'Новый пациент') + '\nhttps://viewer.invalid/#r=' + code


class MockPublisher:
    def __init__(self):
        self.calls = []

    def prepare(self, db, row, moment):
        self.calls.append((row['destination'], row['surname'], row['section']))
        return sealed_message(row['surname'], row['destination'] == 'cardio' and row['section'] == 'orit')


class MockTransport:
    def __init__(self, results=()):
        self.calls = []
        self.results = list(results)

    def send(self, destination, surname):
        self.calls.append((destination, surname))
        result = self.results.pop(0) if self.results else str(len(self.calls))
        if isinstance(result, Exception):
            raise result
        return result


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.temp.name, 'state.sqlite3')
        self.db = n.connect(self.path)
        n.ingest(self.db, book(), moment(), baseline=True)
        self.api = MockTransport()
        self.publisher = MockPublisher()
        def deliver(db, row, prepared):
            return self.api.send(row['destination'], prepared)
        self.publisher.deliver = deliver

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def stable(self, records, when=None, month=10, issues=()):
        when = when or moment()
        b = book(records, month=month, issues=issues)
        n.ingest(self.db, b, when)
        return n.ingest(self.db, b, when)

    def send(self, records, when=None, month=10, issues=()):
        when = when or moment()
        valid = self.stable(records, when, month, issues)
        return n.dispatch(self.db, self.publisher, valid, lambda: when)

    def statuses(self):
        return [x[0] for x in self.db.execute('SELECT status FROM deliveries ORDER BY id')]

    def test_initial_baseline_never_sends_existing(self):
        old = [rec()]
        n.ingest(self.db, book(old), moment(), baseline=True)
        self.assertEqual(self.send(old), 0)
        self.assertEqual(self.api.calls, [])

    def test_new_pso_both_new_orit_only_cardio(self):
        rows = [rec(), rec('Пробов', 21, 'orit')]
        self.assertEqual(self.send(rows), 3)
        self.assertCountEqual(self.api.calls,
                              [('cardio', sealed_message('Тестов')), ('orit', sealed_message('Тестов')), ('cardio', sealed_message('Пробов', True))])

    def test_orit_label_preserves_surname_and_event_identity(self):
        rows = [rec('Тестов', 21, 'orit')]
        valid = self.stable(rows)
        before = tuple(self.db.execute('SELECT id,name_key,surname,fingerprint FROM events').fetchone())
        self.assertEqual(n.dispatch(self.db, self.publisher, valid, lambda: moment()), 1)
        self.assertEqual(self.api.calls, [('cardio', sealed_message('Тестов', True))])
        after = tuple(self.db.execute('SELECT id,name_key,surname,fingerprint FROM events').fetchone())
        self.assertEqual(before, after)
        self.assertEqual(self.send(rows), 0)

    def test_already_delivered_orit_before_update_is_not_resent(self):
        rows = [rec('Тестов', 21, 'orit')]
        valid = self.stable(rows)
        # Simulate a persisted successful send from the previous program version.
        with self.db:
            self.db.execute("UPDATE deliveries SET status='sent',message_id='previous-version-id'")
        self.db.close()
        self.db = n.connect(self.path)
        n.recover(self.db)
        self.assertEqual(self.send(rows), 0)
        self.assertEqual(self.api.calls, [])
        self.assertEqual(self.db.execute('SELECT message_id FROM deliveries').fetchone()[0], 'previous-version-id')

    def test_orit_transfer_excluded_other_transfer_both(self):
        rows = [rec('Пробов', 27, 'transfer', routes=[], origin='ОРИТ-2'),
                rec('Тестов', 28, 'transfer', routes=['cardio', 'orit'], origin='Хирургия')]
        self.assertEqual(self.send(rows), 2)
        self.assertTrue(all(name == sealed_message('Тестов') for _, name in self.api.calls))

    def test_different_surnames_with_same_mask_remain_distinct(self):
        rows = [rec('Петров', 13), rec('Пешков', 14)]
        self.assertEqual(self.send(rows), 4)
        self.assertEqual(self.api.calls,
                         [('cardio', sealed_message('Петров')), ('orit', sealed_message('Петров')),
                          ('cardio', sealed_message('Пешков')), ('orit', sealed_message('Пешков'))])
        stored = [tuple(x) for x in self.db.execute(
            'SELECT surname,name_key FROM events ORDER BY id')]
        self.assertEqual([x[0] for x in stored], ['Петров', 'Пешков'])
        self.assertTrue(all(len(x[1]) == 64 and x[1] not in ('петров', 'пешков') for x in stored))
        self.assertEqual(self.send(rows), 0)

    def test_encrypted_names_keep_case_and_handle_short_and_compound_surnames(self):
        names = [('Ли', 'Ли'), ('Юн', 'Юн'), ('Ёжов', 'Ёж**'),
                 ('ПЕТРОВА', 'ПЕ*****'), ('Иванов-Петров', 'Ив***********'),
                 ('де Голль', 'де******')]
        rows = [rec(name, row=13 + i) for i, (name, _) in enumerate(names)]
        self.assertEqual(self.send(rows), 2 * len(rows))
        self.assertEqual(self.api.calls,
                         [(destination, sealed_message(name)) for name, _ in names
                          for destination in ('cardio', 'orit')])

    def test_identical_names_two_rows_two_events(self):
        self.assertEqual(self.send([rec(), rec(row=14)]), 4)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM events').fetchone()[0], 2)

    def test_identical_names_different_sections_not_collapsed(self):
        self.assertEqual(self.send([rec(), rec(row=21, section='orit')]), 3)

    def test_identical_names_different_days_not_collapsed(self):
        rows = [rec(), rec(date='2026-10-15')]
        self.assertEqual(self.send(rows, moment(day=15)), 4)

    def test_saved_again_no_duplicate(self):
        self.send([rec()])
        self.assertEqual(self.send([rec()]), 0)
        self.assertEqual(len(self.api.calls), 2)

    def test_durable_after_restart(self):
        self.send([rec()])
        self.db.close()
        self.db = n.connect(self.path)
        n.recover(self.db)
        self.assertEqual(self.send([rec()]), 0)

    def test_not_sent_until_second_stable_snapshot(self):
        valid = n.ingest(self.db, book([rec()]), moment())
        self.assertEqual(n.dispatch(self.db, self.publisher, valid, lambda: moment()), 0)
        self.assertEqual(self.send([rec()]), 2)

    def test_empty_origin_then_entered_routes(self):
        first = rec(section='transfer', row=27, routes=[], origin='')
        self.assertEqual(self.send([first]), 0)
        complete = rec(section='transfer', row=27, routes=['cardio', 'orit'], origin='Терапия')
        self.assertEqual(self.send([complete]), 2)

    def test_name_correction_before_send_uses_latest_surname(self):
        n.ingest(self.db, book([rec('Тесто')]), moment())
        self.assertEqual(self.send([rec('Тестов')]), 2)
        self.assertTrue(all(name == sealed_message('Тестов') for _, name in self.api.calls))

    def test_name_correction_after_send_requires_review(self):
        self.send([rec()])
        self.assertEqual(self.send([rec('Тестова')]), 0)
        self.assertTrue(self.db.execute('SELECT review FROM events WHERE active=1').fetchone()[0])

    def test_row_move_after_send_no_duplicate(self):
        self.send([rec()])
        self.assertEqual(self.send([rec(row=15)]), 0)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM events').fetchone()[0], 1)

    def test_row_swap_after_send_no_duplicate(self):
        self.send([rec(), rec('Пробов', row=14)])
        self.assertEqual(self.send([rec('Пробов'), rec(row=14)]), 0)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM events').fetchone()[0], 2)

    def test_moved_old_and_new_at_old_slot_sends_only_new(self):
        self.send([rec()])
        self.assertEqual(self.send([rec('Пробов'), rec(row=14)]), 2)
        self.assertEqual(self.api.calls[-2:], [('cardio', sealed_message('Пробов')), ('orit', sealed_message('Пробов'))])

    def test_invalid_source_slot_prevents_pending_send(self):
        self.stable([rec()])
        issue = dict(date='2026-10-14', section='pso', row=13, kind='name')
        valid = n.ingest(self.db, book([], issues=[issue]), moment())
        self.assertEqual(n.dispatch(self.db, self.publisher, valid, lambda: moment()), 0)
        self.assertEqual(self.send([rec()]), 2)

    def test_pending_deleted_row_not_sent(self):
        self.stable([rec()])
        self.assertEqual(self.send([]), 0)
        self.assertEqual(self.statuses(), ['cancelled', 'cancelled'])

    def test_already_sent_temporarily_deleted_not_resent(self):
        self.send([rec()])
        self.send([])
        self.assertEqual(self.send([rec()]), 0)

    def test_before_activation_date_ignored_even_if_added_later(self):
        self.assertEqual(self.send([rec(date='2026-10-13')]), 0)

    def test_next_month_record_is_not_silently_baselined(self):
        self.assertEqual(self.send([rec(date='2026-11-01')], moment(day=1, month=11), month=11), 2)

    def test_future_record_waits_for_its_day(self):
        rows = [rec(date='2026-10-15')]
        self.assertEqual(self.send(rows), 0)
        self.assertEqual(self.send(rows, moment(day=15)), 2)

    def test_night_queue_sends_in_morning(self):
        self.assertEqual(self.send([rec()], moment(hour=23)), 0)
        self.assertEqual(self.send([rec()], moment(day=15, hour=7)), 2)

    def test_activation_date_is_chelyabinsk_date_even_when_clock_is_utc(self):
        # 23:30 UTC on14October is04:30 on15October in Chelyabinsk.
        utc = dt.datetime(2026, 10, 14, 23, 30, tzinfo=dt.timezone.utc)
        n.ingest(self.db, book(), utc, baseline=True)
        self.assertEqual(n.meta(self.db, 'started_date'), '2026-10-15')
        self.assertEqual(self.send([rec(date='2026-10-14')], moment(day=15, hour=7)), 0)
        self.assertEqual(self.send([rec(date='2026-10-15')], moment(day=15, hour=7)), 2)

    def test_dispatch_uses_chelyabinsk_date_when_host_clock_has_other_zone(self):
        # 23:00 UTC-8 on13October is12:00 on14October in Chelyabinsk.
        other_zone = dt.datetime(2026, 10, 13, 23, tzinfo=dt.timezone(dt.timedelta(hours=-8)))
        self.assertEqual(self.send([rec(date='2026-10-14')], other_zone), 2)

    def test_month_boundary_keeps_last_night_and_new_month_queue_without_duplicates(self):
        october = book([rec(date='2026-10-31')])
        november = book([rec('Пробов', date='2026-11-01')], month=11)
        night = moment(day=31, hour=23)
        n.ingest(self.db, october, night)
        valid = n.ingest(self.db, october, night)
        self.assertEqual(n.dispatch(self.db, self.publisher, valid, lambda: night), 0)
        morning = moment(day=1, hour=7, month=11)
        for _ in range(2):
            valid = n.ingest(self.db, october, morning) + n.ingest(self.db, november, morning)
        self.assertEqual(n.dispatch(self.db, self.publisher, valid, lambda: morning), 4)
        valid = n.ingest(self.db, october, morning) + n.ingest(self.db, november, morning)
        self.assertEqual(n.dispatch(self.db, self.publisher, valid, lambda: morning), 0)

    def test_filename_and_row_changes_preserve_durable_event_identity(self):
        original = book([rec()])
        original['filename'] = '/synthetic/10_October.xlsx'
        n.ingest(self.db, original, moment())
        valid = n.ingest(self.db, original, moment())
        self.assertEqual(n.dispatch(self.db, self.publisher, valid, lambda: moment()), 2)
        moved = book([rec(row=17)])
        moved['filename'] = '/synthetic/Subdivisions/10_October_renamed.xlsx'
        n.ingest(self.db, moved, moment())
        valid = n.ingest(self.db, moved, moment())
        self.assertEqual(n.dispatch(self.db, self.publisher, valid, lambda: moment()), 0)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM events').fetchone()[0], 1)

    def test_window_boundaries_and_timezone(self):
        self.assertFalse(n.in_window(moment(hour=6, minute=59)))
        self.assertTrue(n.in_window(moment(hour=7)))
        self.assertTrue(n.in_window(moment(hour=21, minute=59)))
        self.assertFalse(n.in_window(moment(hour=22)))
        self.assertTrue(n.in_window(dt.datetime(2026, 10, 14, 2, tzinfo=dt.timezone.utc)))
        self.assertFalse(n.in_window(dt.datetime(2026, 10, 14, 17, tzinfo=dt.timezone.utc)))

    def test_window_rechecked_between_individual_messages(self):
        valid = self.stable([rec()])
        times = iter([moment(hour=21, minute=59), moment(hour=21, minute=59), moment(hour=21, minute=59), moment(hour=22)])
        self.assertEqual(n.dispatch(self.db, self.publisher, valid, lambda: next(times)), 1)
        self.assertEqual(self.statuses(), ['sent', 'pending'])

    def test_unknown_response_waits_retry_delay(self):
        self.api = MockTransport([n.ApiFailure('uncertain', 'synthetic timeout')])
        self.assertEqual(self.send([rec()]), 0)
        self.assertEqual(self.statuses(), ['pending', 'pending'])
        self.send([rec()])
        self.assertEqual(len([x for x in self.api.calls if x[0] == 'cardio']), 1)

    def test_first_chat_sent_second_uncertain_keeps_first_complete(self):
        self.api = MockTransport(['1', n.ApiFailure('uncertain', 'synthetic timeout')])
        self.assertEqual(self.send([rec()]), 1)
        self.assertEqual(self.statuses(), ['sent', 'pending'])
        self.assertEqual(self.send([rec()]), 0)
        self.assertEqual(len(self.api.calls), 2)

    def test_crash_during_send_retries_same_prepared_message(self):
        self.stable([rec()])
        with self.db:
            self.db.execute("UPDATE deliveries SET status='sending' WHERE destination='cardio'")
        n.recover(self.db)
        self.assertEqual(self.statuses(), ['pending', 'pending'])

    def test_auth_error_is_blocked_not_retried_each_cycle(self):
        self.api = MockTransport([n.ApiFailure('blocked', 'synthetic 403')])
        self.send([rec()])
        self.send([rec()])
        self.assertEqual(len([x for x in self.api.calls if x[0] == 'cardio']), 1)

    def test_rate_limit_cooldown_survives_cycles(self):
        self.api = MockTransport([n.ApiFailure('retry', 'synthetic 429', 180)])
        self.assertEqual(self.send([rec()], moment(hour=12)), 0)
        self.assertEqual(self.send([rec()], moment(hour=12, minute=1)), 0)
        self.assertEqual(len(self.api.calls), 1)
        self.assertEqual(self.send([rec()], moment(hour=12, minute=3)), 2)

    def test_missing_valid_snapshot_cannot_drain_stale_queue(self):
        self.stable([rec()])
        self.assertEqual(n.dispatch(self.db, self.publisher, [], lambda: moment()), 0)

    def test_stop_before_send_sends_nothing(self):
        valid = self.stable([rec()])
        self.assertEqual(n.dispatch(self.db, self.publisher, valid, lambda: moment(),
                                    should_stop=lambda: True), 0)
        self.assertEqual(self.api.calls, [])

    def test_stop_between_chats_preserves_remaining_queue(self):
        valid = self.stable([rec()])
        self.assertEqual(n.dispatch(self.db, self.publisher, valid, lambda: moment(),
                                    should_stop=lambda: bool(self.api.calls)), 1)
        self.assertEqual(self.statuses(), ['sent', 'pending'])

    def test_moved_active_identical_surname_beats_inactive_old_slot(self):
        self.send([rec()])  # old person already sent in row 13
        n.ingest(self.db, book([rec(), rec(row=14)]), moment())  # another same surname
        n.ingest(self.db, book([rec(row=14)]), moment())  # old row removed
        self.assertEqual(self.send([rec(row=13)]), 2)  # remaining person moved up
        self.assertEqual(len(self.api.calls), 4)

    def test_new_identical_row_above_does_not_steal_unchanged_exact_match(self):
        self.send([rec(row=14)])  # old person already sent
        n.ingest(self.db, book([rec(row=13), rec(row=14)]), moment())
        self.assertEqual(self.send([rec(row=14)]), 0)  # new row13 deleted before dispatch
        self.assertEqual(len(self.api.calls), 2)


if __name__ == '__main__':
    unittest.main()
