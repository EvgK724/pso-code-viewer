#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ПСО → Просмотрщик. Run with Python 3.7+, without sudo or third-party packages."""
import argparse
import contextlib
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import shutil
import shlex
import signal
import ssl
import subprocess
import sys
import time
from urllib.parse import unquote, urlparse, parse_qs

from xlsx_reader import read_book, ReaderError
from notifier import (DESTINATIONS, ApiFailure, connect, ingest, dispatch, prune,
                      recover, now, in_window, meta, set_meta)
from team_crypto import OpenSSLIdentity, unb64, read_card
from team_publish import (TeamClient, TeamPublisher, TeamFailure, service_config,
                          parse_invitation, reset_prepared_after_review)

ROOT = Path(__file__).resolve().parent
DATA = Path.home() / '.local' / 'share' / 'pso-viewer-bot'
OLD_DATA = Path.home() / '.local' / 'share' / 'pso-pachca'
MONTHS = ('Январь Февраль Март Апрель Май Июнь Июль Август Сентябрь Октябрь Ноябрь Декабрь').split()
POLL = 60
VERSION = '1.3 — независимая отправка по направлениям'


def prepare():
    os.umask(0o077)
    DATA.mkdir(parents=True, exist_ok=True)
    os.chmod(str(DATA), 0o700)


def atomic_json(path, value):
    temp = path.with_suffix(path.suffix + '.tmp')
    with temp.open('w', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(str(temp), 0o600)
    os.replace(str(temp), str(path))


@contextlib.contextmanager
def exclusive():
    with (DATA / 'worker.lock').open('a') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Программа уже работает. Для изменения настройки сначала выберите «Остановить».')
        yield


def running():
    try:
        with exclusive():
            return False
    except RuntimeError:
        return True


def config():
    try:
        return json.loads((DATA / 'config.json').read_text(encoding='utf-8'))
    except (OSError, ValueError):
        raise RuntimeError('Сначала выполните пункт «Настроить месячный файл».')


def resolve_path(text):
    text = text.strip()
    # File managers may paste either a plain path or a shell-quoted/escaped path.
    if text.startswith(('"', "'")) or '\\' in text:
        try:
            tokens = shlex.split(text)
            if len(tokens) == 1:
                text = tokens[0]
        except ValueError:
            raise RuntimeError('Не удалось разобрать путь: проверьте кавычки или выберите файл через окно.')
    parsed = urlparse(text)
    if parsed.scheme == 'file':
        if parsed.netloc not in ('', 'localhost'):
            raise RuntimeError('Выберите файл через подключённую общую папку на компьютере.')
        text = unquote(parsed.path)
    elif parsed.scheme == 'smb':
        # Reuse an already mounted share; never mount or request server credentials.
        parts = unquote(parsed.path).lstrip('/').split('/', 1)
        share, tail = parts[0], parts[1] if len(parts) > 1 else ''
        base = Path('/run/user') / str(os.getuid()) / 'gvfs'
        for mount in base.glob('smb-share:*'):
            pairs = dict(item.split('=', 1) for item in mount.name[10:].split(',') if '=' in item)
            if pairs.get('server', '').casefold() == (parsed.hostname or '').casefold() and pairs.get('share', '').casefold() == share.casefold():
                return (mount / tail).resolve()
        raise RuntimeError('Папка отчётов не подключена для Python. Откройте её в файловом менеджере и выберите файл ещё раз; нужен путь к доступному файлу.')
    return Path(text).expanduser().resolve()


def choose_path():
    print('Выберите действующий месячный файл из папки «Подразделения», который заполняют врачи.')
    answer = input('Нажмите Enter для окна выбора или вставьте полный путь к XLSX: ').strip()
    if not answer:
        root = None
        try:
            import tkinter as tk
            from tkinter import filedialog
            root = tk.Tk()
            root.withdraw()
            answer = filedialog.askopenfilename(title='Действующий месячный отчёт ПСО', filetypes=[('Excel', '*.xlsx')])
        except Exception:
            print('Окно выбора недоступно. Вставьте путь из свойств файла или перетащите файл в терминал.')
        finally:
            if root is not None:
                root.destroy()
        if not answer:
            answer = input('Полный путь к XLSX: ').strip()
    if not answer:
        raise RuntimeError('Файл не выбран; настройки не изменены.')
    return resolve_path(answer)


def imported_config():
    """Read only source paths; never copy the old bot's token, keys or queue."""
    try:
        value = json.loads((OLD_DATA / 'config.json').read_text(encoding='utf-8'))
        if not isinstance(value, dict) or not isinstance(value.get('sources'), dict):
            return None
        return {key: value[key] for key in ('sources', 'folder', 'anchor_year', 'anchor_month')}
    except (OSError, ValueError, KeyError):
        return None


def setup():
    with exclusive():
        existing = json.loads((DATA / 'config.json').read_text(encoding='utf-8')) if (DATA / 'config.json').exists() else None
        imported = imported_config() if not existing else None
        cfg = existing or {'sources': {}}
        path = None
        if imported:
            key = now().strftime('%Y-%m')
            candidate = imported['sources'].get(key)
            if not candidate:
                candidate = str(Path(imported['folder']) / '{:02d}_{}.xlsx'.format(now().month, MONTHS[now().month - 1]))
            if Path(candidate).is_file():
                print('Найден путь к текущему отчёту в настройке прежнего бота. Его настройка не меняется.')
                answer = input('Enter — использовать этот отчёт; 1 — выбрать другой: ').strip()
                if not answer:
                    path = Path(candidate)
        if path is None:
            path = choose_path()
        book = read_book(path)
        if book['issues']:
            print('\n'.join(book['warnings']))
            raise RuntimeError('Сначала исправьте указанные ячейки и сохраните отчёт. Первый запуск требует полного исходного снимка.')
        month_key = '{:04d}-{:02d}'.format(book['year'], book['month'])
        cfg['sources'][month_key] = str(path)
        cfg['folder'], cfg['anchor_year'], cfg['anchor_month'] = str(path.parent), book['year'], book['month']
        db = connect(DATA / 'state.sqlite3')
        first = meta(db, 'initialized') != '1'
        ingest(db, book, now(), baseline=first)
        prune(db, now())
        db.close()
        atomic_json(DATA / 'config.json', cfg)
        print('Месяц {:02d}.{} настроен; история отправок сохранена.'.format(book['month'], book['year']))
        if first:
            print('Уже заполненные строки приняты за исходные и отправляться не будут.')
        print('Подключите новый бот в пункте 8, подтвердите его в просмотрщике и выберите «Запустить в фоне».')
        print('Токен Пачки не нужен. Старый бот работает независимо.')


def find_months(cfg, moment):
    """Add subsequent canonical monthly files in the same year/folder."""
    issues = []
    year = cfg['anchor_year']
    if moment.year != year:
        issues.append('Сменился год: выберите новый месячный файл в настройке; история сохранится.')
    last = moment.month if moment.year == year else 12
    for month in range(cfg['anchor_month'], last + 1):
        key = '{:04d}-{:02d}'.format(year, month)
        if key in cfg['sources']:
            if not Path(cfg['sources'][key]).is_file():
                issues.append('Выбранный файл {} недоступен. Ожидаю восстановления доступа; другую копию автоматически не выбираю.'.format(key))
            continue
        candidate = Path(cfg['folder']) / '{:02d}_{}.xlsx'.format(month, MONTHS[month - 1])
        if candidate.is_file():
            cfg['sources'][key] = str(candidate)
        else:
            issues.append('Не найден месячный файл {}. Выберите его в настройке.'.format(candidate.name))
    return issues


def counts(db):
    return {x[0]: x[1] for x in db.execute('SELECT status,COUNT(*) FROM deliveries GROUP BY status')}


def notify_problem():
    command = shutil.which('notify-send')
    if command:
        try:
            subprocess.run([command, 'ПСО → Просмотрщик', 'Отправка требует проверки. Откройте программу → Состояние.'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass


def worker():
    with exclusive():
        cfg = config()
        db = connect(DATA / 'state.sqlite3')
        if meta(db, 'initialized') != '1':
            raise RuntimeError('Нет исходного снимка. Сначала выполните настройку.')
        recover(db)
        publisher = encrypted_publisher(db)
        stop = DATA / 'stop.request'
        if stop.exists():
            stop.unlink()
        stopped = [False]
        def stop_signal(signum, frame):
            stopped[0] = True
        signal.signal(signal.SIGTERM, stop_signal)
        signal.signal(signal.SIGINT, stop_signal)
        last_problem = None
        while not stopped[0] and not stop.exists():
            moment = now()
            try:
                problems = find_months(cfg, moment)
            except OSError:
                problems = ['Папка отчётов временно недоступна; повторю проверку через минуту.']
            atomic_json(DATA / 'config.json', cfg)
            valid = []
            for key, filename in sorted(cfg['sources'].items()):
                try:
                    book = read_book(filename)
                    if key != '{:04d}-{:02d}'.format(book['year'], book['month']):
                        raise ReaderError('Месяц внутри книги не совпадает с выбранным источником.')
                    valid.extend(ingest(db, book, moment))
                    problems.extend(book['warnings'])
                except ReaderError as exc:
                    problems.append('{}: {}'.format(key, exc))
            if in_window(moment) and moment.timestamp() >= float(meta(db, 'retry_after', '0')):
                try:
                    publisher.team.require_bot()
                    if valid:
                        dispatch(db, publisher, valid, should_stop=lambda: stopped[0] or stop.exists())
                    # All pending viewer notices, including doctors' reviews, can
                    # be retried by an active bot. Stored inbox entries are durable
                    # whether a phone accepted its push notification or not.
                    if not stopped[0] and not stop.exists() and in_window(now()):
                        publisher.team.retry_notifications()
                except (ApiFailure, TeamFailure) as exc:
                    problems.append(exc.note)
                    if exc.kind == 'retry':
                        with db:
                            set_meta(db, 'retry_after', now().timestamp() + getattr(exc, 'retry_after', 60))
            prune(db, moment)
            report = counts(db)
            review = db.execute("SELECT COUNT(*) FROM events WHERE review<>'' AND active=1 AND baseline=0").fetchone()[0]
            if report.get('blocked', 0):
                problems.append('Часть отправок требует проверки. Проверьте получателей в пункте 9 и записи в пункте «Разобрать вопросы».')
            if review:
                problems.append('Есть изменённые строки: пункт «Разобрать вопросы».')
            atomic_json(DATA / 'status.json', {'updated': now().isoformat(), 'mode': 'работает' if in_window(now()) else 'пауза до 07:00',
                                               'counts': report, 'problems': problems, 'review': review})
            signature = '\n'.join(problems)
            if signature and signature != last_problem:
                notify_problem()
            last_problem = signature
            for _ in range(POLL):
                if stopped[0] or stop.exists():
                    break
                time.sleep(1)
        db.close()
        atomic_json(DATA / 'status.json', {'updated': now().isoformat(), 'mode': 'остановлена', 'counts': report if 'report' in locals() else {}, 'problems': []})


def start():
    config()
    TeamClient(OpenSSLIdentity(DATA / 'crypto')).require_bot()
    if running():
        print('Программа уже работает. Повторный экземпляр не запущен.')
        return
    logfile = DATA / 'run.log'
    if logfile.exists() and logfile.stat().st_size > 1024 * 1024:
        os.replace(str(logfile), str(DATA / 'run_previous.log'))
    with logfile.open('a') as stream:
        subprocess.Popen([sys.executable, str(ROOT / 'pso_viewer.py'), 'run'],
                         stdin=subprocess.DEVNULL, stdout=stream, stderr=stream,
                         cwd=str(ROOT), start_new_session=True)
    time.sleep(0.5)
    if not running():
        raise RuntimeError('Не удалось запустить программу. Смотрите ' + str(logfile))
    print('Запущено в фоне. Терминал можно закрыть. Отправка 07:00–22:00 по Челябинску.')
    print('Первые новые записи будут проверены на двух чтениях с интервалом 60 секунд.')


def stop_worker():
    if not running():
        print('Программа уже остановлена.')
        return
    (DATA / 'stop.request').touch()
    print('Запрошена остановка. Она завершится после текущего сетевого запроса, обычно до 40 секунд.')


def status():
    print('Версия: ' + VERSION)
    print('Получатель: ' + service_config()['viewer_url'])
    print('Процесс: ' + ('работает' if running() else 'не запущен'))
    path = DATA / 'status.json'
    if path.exists():
        value = json.loads(path.read_text(encoding='utf-8'))
        print('Последняя проверка: {}. {}'.format(value['updated'], value['mode']))
        labels = {'pending': 'Ожидают подтверждения', 'sent': 'Сохранены во входящих',
                  'blocked': 'Нужна проверка', 'cancelled': 'Отменены', 'sending': 'Отправляются'}
        for key, amount in value.get('counts', {}).items():
            print('{}: {}'.format(labels.get(key, key), amount))
        for item in value.get('problems', []):
            print('! ' + item)
    else:
        print('Проверок ещё не было.')
    print('Время на компьютере для расписания: ' + now().strftime('%d.%m.%Y %H:%M') + ' (UTC+5).')


def preview():
    cfg = config()
    for key, filename in sorted(cfg['sources'].items()):
        book = read_book(filename)
        print('{}: заполнено {} строк; маршруты до учёта истории: кардиолог {}, реаниматолог {}.'.format(
            key, len(book['records']), sum('cardio' in x['routes'] for x in book['records']),
            sum('orit' in x['routes'] for x in book['records'])))
        for line in book['warnings']:
            print('! ' + line)
    print('Это проверка чтения; сообщений не отправляла и очередь не меняла.')


def resolve():
    with exclusive():
        db = connect(DATA / 'state.sqlite3')
        recover(db)
        for event in db.execute("SELECT * FROM events WHERE review<>'' AND active=1 AND baseline=0").fetchall():
            print('\n{} / {} / B{}: {}. {}'.format(event['date'], event['section'], event['rownum'], event['surname'], event['review']))
            answer = input('Это новый пациент? д — разрешить недоставленные уведомления; н — не отправлять; Enter — позже: ').lower().strip()
            with db:
                if answer == 'д':
                    db.execute("UPDATE events SET review='' WHERE id=?", (event['id'],))
                elif answer == 'н':
                    db.execute("UPDATE events SET review='',baseline=1 WHERE id=?", (event['id'],))
                    db.execute("UPDATE deliveries SET status='cancelled' WHERE event_id=? AND status IN ('pending','blocked')", (event['id'],))
        rows = db.execute("""SELECT d.*,e.date,e.rownum,e.surname,e.section FROM deliveries d JOIN events e ON e.id=d.event_id
                             WHERE d.status='blocked' ORDER BY d.id""").fetchall()
        for row in rows:
            print('\n{} / {} / B{} → {}. {}'.format(row['date'], row['section'], row['rownum'], DESTINATIONS[row['destination']], row['note']))
            print('Запись могла сохраниться во входящих до сбоя связи. Повтор с прежним кодом безопасен.')
            answer = input('1 — повторить прежнюю запись; 2 — отменить; 3 — после проверки создать новую запись; Enter — позже: ').strip()
            if answer == '3':
                confirm = input('Проверили входящие и разрешаете создать новую запись (может дать повторное уведомление)? д — да: ').lower().strip()
                if confirm == 'д':
                    reset_prepared_after_review(db, row['id'])
                continue
            with db:
                if answer == '1':
                    db.execute("UPDATE deliveries SET status='pending',note='' WHERE id=?", (row['id'],))
                elif answer == '2':
                    db.execute("UPDATE deliveries SET status='cancelled',note='Отменено организатором' WHERE id=?", (row['id'],))
        db.close()
    print('Решения сохранены. Для продолжения выберите «Запустить в фоне».')


def encrypted_publisher(db):
    return TeamPublisher(db, TeamClient(OpenSSLIdentity(DATA / 'crypto')))


def activation_details(value, team=None):
    if team is not None:
        return team.resolve_invitation(value)
    reference = parse_invitation(value, service_config()['viewer_url'])
    if reference['organizerHash']:
        raise ValueError('Для короткого приглашения выберите пункт «Подключить новый бот к просмотрщику».')
    return reference['id'], reference['organizerCard']


def activation_id(value):
    return activation_details(value)[0]


def pin_organizer(card):
    identity = read_card(card)
    path = DATA / 'organizer.card'
    if path.exists():
        existing = read_card(path.read_text(encoding='utf-8').strip())
        if existing['id'] != identity['id']:
            raise RuntimeError('Ключ организатора изменился. Замена не выполнена: сначала проверьте это лично с организатором.')
        return
    fingerprint = unb64(identity['id'], 32).hex().upper()
    print('Ключ организатора: ' + ' '.join(fingerprint[i:i+4] for i in range(0, len(fingerprint), 4)))
    answer = input('Ссылка получена лично от вашего организатора и контрольный код сверен? д — подтвердить: ').lower().strip()
    if answer != 'д':
        raise RuntimeError('Ключ не закреплён. Подключение не выполнено.')
    temp = DATA / 'organizer.card.tmp'
    temp.write_text(card + '\n', encoding='utf-8')
    os.chmod(str(temp), 0o600)
    os.replace(str(temp), str(path))


def setup_encryption():
    with exclusive():
        identity = OpenSSLIdentity(DATA / 'crypto', create=True)
        version = identity.run(['version']).decode('ascii', 'replace').strip()
        print('Шифрование: ' + version)
        print('Ключи созданы для этого бота и сохранены только в вашей учётной записи.')
        fingerprint = unb64(identity.id, 32).hex().upper()
        print('Контрольный код бота: ' + ' '.join(fingerprint[i:i+4] for i in range(0, len(fingerprint), 4)))
        invite = input('Вставьте персональную ссылку активации с ролью «Бот» (Enter — только проверить): ').strip()
        if invite:
            team = TeamClient(identity)
            invitation_id, organizer_card = activation_details(invite, team)
            if organizer_card:
                pin_organizer(organizer_card)
            elif not (DATA / 'organizer.card').is_file():
                raise RuntimeError('В приглашении нет ключа организатора. Создайте новое приглашение в обновлённом просмотрщике.')
            # Claim only follows the existing explicit organizer-key confirmation.
            result = team.claim(invitation_id)
            print('Заявка принята. Администратор должен подтвердить этот контрольный код.' if result['state'] == 'pending' else 'Активация подтверждена. Проверьте пункт 9.')
        else:
            print('Для подключения нужна персональная ссылка от администратора просмотрщика.')
        print('Файл отчёта и история нового бота сохранены; прежний бот не изменён.')


def encryption_status():
    print('HTTPS в Python: ' + ssl.OPENSSL_VERSION)
    identity = OpenSSLIdentity(DATA / 'crypto')
    print('Шифрование: ' + identity.run(['version']).decode('ascii', 'replace').strip())
    team = TeamClient(identity)
    value = team.status()
    labels = {'unregistered': 'не подключён', 'pending': 'ждёт подтверждения администратора',
              'active': 'активен', 'revoked': 'доступ отозван'}
    print('Бот: ' + labels[value['state']])
    if value['state'] == 'active' and value.get('role') == 'bot':
        for destination, label in [('cardio', 'Кардиолог'), ('orit', 'Реаниматологи')]:
            try:
                recipients = team.recipients(destination)
            except TeamFailure as exc:
                if exc.kind != 'blocked' or exc.code != 'no_recipients':
                    raise
                print('{}: активных получателей 0. Отсутствие получателей этого направления не задерживает другое.'.format(label))
            else:
                print('{}: активных получателей {}'.format(label, len(recipients)))
    elif value['state'] == 'active':
        print('Устройство имеет другую роль. Отправка поступлений заблокирована.')
    print('Проверка не отправляет сообщения пациентам или врачам.')


def desktop_quote(value):
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"').replace('`', '\\`').replace('$', '\\$').replace('%', '%%') + '"'


def autostart():
    config()
    target = Path.home() / '.config' / 'autostart' / 'pso-viewer-bot.desktop'
    target.parent.mkdir(parents=True, exist_ok=True)
    content = ('[Desktop Entry]\nType=Application\nName=ПСО — уведомления просмотрщика\n'
               'Comment=Зашифрованные уведомления ПСО с 07 до 22 часов\n'
               'Exec={} {} start\nTerminal=false\nX-GNOME-Autostart-enabled=true\n').format(
                   desktop_quote(sys.executable), desktop_quote(ROOT / 'pso_viewer.py'))
    target.write_text(content, encoding='utf-8')
    print('Автозапуск добавлен для вашей учётной записи после входа в Linux.')
    print('Папку с программой теперь не перемещайте. После перезагрузки нужен обычный вход пользователя.')


def menu():
    actions = {'1': setup, '2': start, '3': status, '4': autostart,
               '5': stop_worker, '6': resolve, '7': preview, '8': setup_encryption, '9': encryption_status}
    while True:
        print('\nПСО → Просмотрщик | Версия ' + VERSION + '\n' +
              service_config()['viewer_url'] + '\n07:00–22:00 | Челябинск\n'
              '1. Настроить месячный файл\n2. Запустить в фоне\n3. Состояние\n'
              '4. Включить автозапуск после входа\n5. Остановить\n'
              '6. Разобрать вопросы (после остановки)\n7. Проверить чтение файла\n'
              '8. Подключить новый бот к просмотрщику\n9. Проверить подключение и получателей\n0. Закрыть меню')
        choice = input('Выберите номер: ').strip()
        if choice == '0':
            break
        try:
            if choice in actions:
                actions[choice]()
        except (RuntimeError, ReaderError, ApiFailure, OSError, ValueError) as exc:
            print('Не выполнено: ' + str(exc))


def main():
    prepare()
    parser = argparse.ArgumentParser(description='ПСО → Просмотрщик; Python 3.7+, без установки пакетов')
    parser.add_argument('command', nargs='?', default='menu', choices=['menu','setup','start','run','stop','status','preview','resolve','autostart','enroll','crypto-status'])
    args = parser.parse_args()
    actions = {'menu': menu, 'setup': setup, 'start': start, 'run': worker, 'stop': stop_worker,
               'status': status, 'preview': preview, 'resolve': resolve, 'autostart': autostart,
               'enroll': setup_encryption, 'crypto-status': encryption_status}
    try:
        actions[args.command]()
    except (RuntimeError, ReaderError, ApiFailure, OSError, ValueError) as exc:
        print('Не выполнено: ' + str(exc), file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print('\nМеню закрыто; работа фонового процесса не менялась.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
