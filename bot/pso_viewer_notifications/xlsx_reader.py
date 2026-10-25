"""Read saved PSO monthly workbooks, without modifying them (Python 3.7+).

Only B in admission sections and D in transfers are extracted. Formula cached
values are deliberately never accepted for names, source wards or headings.
No patient details are included in exceptions or warnings.
"""
import calendar
import datetime
import io
import os
import posixpath
import re
import unicodedata
import zipfile
import xml.etree.ElementTree as ET


NS = {"s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
REL_ID = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"
DATE_NAME = re.compile(r"^(\d{2})\.(\d{2})\.(\d{2}|\d{4})$")
HEADERS = {
    "A11": "ПОСТУПИВШИЕ В ПСО", "B12": "Ф.И.О.",
    "A19": "ПОСТУПИВШИЕ В ОРИТ", "B20": "Ф.И.О.",
    "A25": "ПЕРЕВЕДЕНЫ В ПСО", "B26": "Ф.И.О.",
    "D26": "Откуда", "A31": "ПЕРЕВЕДЕНЫ ИЗ ПСО",
}
SECTIONS = (("pso", range(13, 19)), ("orit", range(21, 25)),
            ("transfer", range(27, 30)))
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_XML_BYTES = 150 * 1024 * 1024
WORD = r"[A-Za-zА-Яа-яЁё]+(?:[-'’][A-Za-zА-Яа-яЁё]+)*"
WORD_RE = re.compile(r"^" + WORD + r"$")
# An ordinary full name can be reduced only when its structure is recognizable.
# Unknown multiword text is left for correction, never sent verbatim.
GIVEN_NAMES = set("""Александр Александра Алексей Алена Алёна Алина Алла Альберт
Альбина Анатолий Андрей Анжела Анжелика Анна Антон Антонина Аркадий Артем Артём
Артур Борис Вадим Валентин Валентина Валерий Валерия Василий Вера Виктор Виктория
Виталий Владимир Владислав Владислава Вячеслав Галина Геннадий Георгий Глеб
Григорий Даниил Дарья Денис Дмитрий Евгений Евгения Евдокия Екатерина Елена
Елизавета Зинаида Зоя Иван Игорь Инна Ирина Кирилл Клавдия Константин Ксения
Лариса Лев Леонид Лидия Любовь Людмила Максим Маргарита Марина Мария Матвей
Михаил Надежда Наталья Наталия Нелли Никита Николай Нина Оксана Олег Ольга
Павел Петр Пётр Полина Раиса Роман Руслан Светлана Семен Семён Сергей София
Софья Станислав Степан Таисия Тамара Татьяна Тимофей Тимур Федор Фёдор Юлия
Юрий Яна Ярослав Яков Рустам Ринат Ренат Равиль Рашид Марат Фарид Наиль
Рафаэль Рамиль Римма Роза Зульфия Гульнара Гузель Лилия Дина Эльвира Эдуард
Эльмира Валентина Фаина Резеда Илья Захар Эмма Давид Роберт""".casefold().split())
PARTICLES = {"де", "дель", "дю", "да", "ди", "ван", "фон", "ла", "ле", "аль", "эль"}


class ReaderError(Exception):
    """The saved workbook cannot be safely interpreted; do not change state."""


class FileBusyError(ReaderError):
    """The workbook was replaced or changed while reading; retry later."""


def normalize(value):
    """Normalize whitespace and typography; never strip words or digits."""
    value = unicodedata.normalize("NFC", value or "")
    value = value.replace("\u2010", "-").replace("\u2011", "-")
    value = value.replace("\u2013", "-").replace("\u2014", "-")
    return " ".join(value.split())


def name_key(value):
    return normalize(value).casefold().replace("ё", "е")


def extract_surname(value):
    """Return surname only, or None for incomplete/ambiguous input."""
    value = normalize(value)
    if not value or len(value) > 150:
        return None
    if WORD_RE.fullmatch(value) and len(value) >= 2:
        return value
    # Lastname I.I., Lastname I. I., Lastname I I and Lastname I.
    m = re.fullmatch(r"(" + WORD + r")\s+([A-Za-zА-Яа-яЁё]\.?(?:\s*[A-Za-zА-Яа-яЁё]\.?)?)", value)
    if m and len(m.group(1)) >= 2:
        return m.group(1)
    parts = value.split()
    if not all(WORD_RE.fullmatch(p) for p in parts):
        return None
    if len(parts) == 2 and parts[1].casefold() in GIVEN_NAMES:
        return parts[0] if len(parts[0]) >= 2 else None
    if len(parts) == 3 and parts[1].casefold() in GIVEN_NAMES:
        if re.search(r"(?:ович|евич|овна|евна|ична|ич|инична)$", parts[2], re.IGNORECASE):
            return parts[0] if len(parts[0]) >= 2 else None
    # Recognizable surname particles, e.g. "де Голль" or "ван дер Меер".
    if (2 <= len(parts) <= 3 and parts[0].casefold() in PARTICLES
            and len(parts[-1]) >= 2
            and (len(parts) == 2 or parts[1].casefold() in {"дер", "ден", "де", "ла"})):
        return value
    return None


def is_orit(origin):
    value = normalize(origin).upper().replace("Ё", "Е")
    return bool(re.search(r"(?:^|[^А-ЯA-Z])ОРИТ(?:$|[^А-ЯA-Z])", value))


def _stamp(stat):
    return (stat.st_dev, stat.st_ino, stat.st_size,
            getattr(stat, "st_mtime_ns", stat.st_mtime),
            getattr(stat, "st_ctime_ns", stat.st_ctime))


def _snapshot(path):
    try:
        before = os.stat(path)
        if before.st_size > MAX_ARCHIVE_BYTES:
            raise ReaderError("Файл превышает допустимый размер 50 МБ.")
        with open(path, "rb") as source:
            opened = os.fstat(source.fileno())
            data = source.read(MAX_ARCHIVE_BYTES + 1)
            after_read = os.fstat(source.fileno())
        after = os.stat(path)
    except OSError:
        raise ReaderError("Не удалось прочитать файл: проверьте доступ к общей папке.") from None
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ReaderError("Файл превышает допустимый размер 50 МБ.")
    if not (_stamp(before) == _stamp(opened) == _stamp(after_read) == _stamp(after)):
        raise FileBusyError("Файл изменяется или сохраняется; чтение будет повторено.")
    return data


def _xml(archive, member):
    try:
        data = archive.read(member)
        if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
            raise ReaderError("Неподдерживаемая структура XML в файле.")
        return ET.fromstring(data)
    except (KeyError, ET.ParseError, RuntimeError, NotImplementedError):
        raise ReaderError("Не удалось прочитать структуру XLSX; возможно, файл сохраняется.") from None


def _text(container):
    if container is None:
        return ""
    # Only text runs; do not mix phonetic guides or formatting with cell data.
    direct = container.find("s:t", NS)
    if direct is not None:
        return direct.text or ""
    return "".join((run.find("s:t", NS).text or "")
                   for run in container.findall("s:r", NS)
                   if run.find("s:t", NS) is not None)


def _cell_value(cell, shared):
    if cell is None:
        return "", False, True
    if cell.find("s:f", NS) is not None:
        return "", True, False
    kind = cell.get("t")
    if kind == "inlineStr":
        return _text(cell.find("s:is", NS)), False, True
    val = cell.find("s:v", NS)
    raw = val.text if val is not None and val.text is not None else ""
    if kind == "s":
        try:
            index = int(raw)
            if index < 0:
                raise ValueError()
            return shared[index], False, True
        except (ValueError, IndexError):
            raise ReaderError("Повреждена таблица текстовых значений XLSX.") from None
    if kind == "str":
        return raw, False, True
    if not raw:
        return "", False, True
    # Numeric, boolean and Excel error cells are not patient name/ward text.
    return "", False, False


def _sheet_date(name):
    match = DATE_NAME.fullmatch(name)
    if not match:
        # A malformed date-like tab cannot silently disappear from observation.
        if re.match(r"^\d{1,2}\.\d{1,2}\.", name):
            raise ReaderError("Имя дневного листа должно иметь вид ДД.ММ.ГГ.")
        return None
    day, month, year = map(int, match.groups())
    if year < 100:
        year += 2000
    try:
        return datetime.date(year, month, day)
    except ValueError:
        raise ReaderError("Недопустимая дата в имени дневного листа.") from None


def read_book(path):
    """Return {year, month, records, warnings, issues} from one complete month.

    issues items contain only date/section/row/kind ('name', 'origin',
    'origin_blank'). Preserve prior records at invalid name/origin slots until
    corrected. A blank origin produces a record with no routes; once entered,
    it may acquire routes. No dates are filtered here; scheduling is separate.
    """
    data = _snapshot(path)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            if len(members) > 10000 or sum(m.file_size for m in members) > MAX_XML_BYTES:
                raise ReaderError("Слишком большой объём распакованных данных XLSX.")
            names = [m.filename for m in members]
            if len(set(names)) != len(names):
                raise ReaderError("В XLSX обнаружены повторяющиеся части архива.")
            workbook = _xml(archive, "xl/workbook.xml")
            rels_xml = _xml(archive, "xl/_rels/workbook.xml.rels")
            rels = {r.get("Id"): r for r in rels_xml}
            shared = []
            if "xl/sharedStrings.xml" in names:
                shared = [_text(si) for si in _xml(archive, "xl/sharedStrings.xml")]
            sheet_list = workbook.find("s:sheets", NS)
            if sheet_list is None:
                raise ReaderError("В книге не найдены дневные листы.")
            daily = []
            for sheet in sheet_list:
                name = sheet.get("name", "")
                date = _sheet_date(name)
                if date is None:
                    continue
                relation = rels.get(sheet.get(REL_ID))
                if relation is None or relation.get("TargetMode") == "External":
                    raise ReaderError("Недопустимая ссылка на дневной лист.")
                target = relation.get("Target", "")
                member = posixpath.normpath(target.lstrip("/") if target.startswith("/")
                                           else posixpath.join("xl", target))
                if not member.startswith("xl/worksheets/"):
                    raise ReaderError("Недопустимый путь дневного листа внутри XLSX.")
                daily.append((date, name, member))
            if not daily:
                raise ReaderError("В книге не найдены листы с датами ДД.ММ.ГГ.")
            daily.sort()
            year, month = daily[0][0].year, daily[0][0].month
            expected = {datetime.date(year, month, d)
                        for d in range(1, calendar.monthrange(year, month)[1] + 1)}
            actual = [d for d, _, _ in daily]
            if len(actual) != len(expected) or set(actual) != expected:
                raise ReaderError("Дневные листы должны составлять один полный месяц без повторов.")
            output = {"year": year, "month": month, "records": [],
                      "warnings": [], "issues": []}
            for date, name, member in daily:
                tree = _xml(archive, member)
                cells = {}
                for row in tree.findall("s:sheetData/s:row", NS):
                    for cell in row.findall("s:c", NS):
                        address = cell.get("r", "")
                        if address in cells:
                            raise ReaderError("Дублирующийся адрес ячейки на дневном листе.")
                        cells[address] = cell
                for address, expected_text in HEADERS.items():
                    value, formula, valid = _cell_value(cells.get(address), shared)
                    if formula or not valid or normalize(value).upper() != expected_text.upper():
                        raise ReaderError("Лист {0}, ячейка {1}: изменилась структура таблицы.".format(name, address))
                for section, rows in SECTIONS:
                    for row in rows:
                        def issue(kind, column, explanation):
                            output["issues"].append({"date": date.isoformat(), "section": section,
                                                     "row": row, "kind": kind})
                            output["warnings"].append("{0}, {1}{2}: {3}".format(name, column, row, explanation))
                        raw, formula, valid = _cell_value(cells.get("B" + str(row)), shared)
                        if formula or not valid:
                            issue("name", "B", "нужно вписать фамилию текстом, без формулы.")
                            continue
                        if not normalize(raw):
                            continue
                        surname = extract_surname(raw)
                        if surname is None:
                            issue("name", "B", "не удалось однозначно выделить фамилию; проверьте запись.")
                            continue
                        origin = ""
                        routes = ["cardio", "orit"] if section == "pso" else ["cardio"]
                        if section == "transfer":
                            origin, formula, valid = _cell_value(cells.get("D" + str(row)), shared)
                            if formula or not valid:
                                issue("origin", "D", "нужно вписать исходное отделение текстом, без формулы.")
                                continue
                            origin = normalize(origin).upper()
                            if not origin:
                                routes = []
                                issue("origin_blank", "D", "не указано исходное отделение; отправка ожидает заполнения.")
                            else:
                                routes = [] if is_orit(origin) else ["cardio", "orit"]
                        output["records"].append({"date": date.isoformat(), "section": section,
                                                  "row": row, "surname": surname,
                                                  "name_key": name_key(raw), "origin": origin,
                                                  "routes": routes})
            return output
    except (zipfile.BadZipFile, EOFError, OSError):
        raise ReaderError("Не удалось прочитать сохранённый XLSX; повторите после завершения сохранения.") from None
