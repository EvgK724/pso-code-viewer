"""Synthetic reader tests; no hospital records or network access."""
import calendar
import os
import tempfile
import unittest
import zipfile
import xml.etree.ElementTree as ET

from xlsx_reader import (HEADERS, NS, ReaderError, extract_surname, is_orit,
                         read_book)

S = NS["s"]
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
P = "http://schemas.openxmlformats.org/package/2006/relationships"


def fixture(path, overrides=None, year=2026, month=10, missing_day=None,
            header_change=None, shared=None):
    overrides = overrides or {}
    workbook = ET.Element("{" + S + "}workbook")
    sheets = ET.SubElement(workbook, "{" + S + "}sheets")
    rels = ET.Element("{" + P + "}Relationships")
    with zipfile.ZipFile(path, "w") as archive:
        for day in range(1, calendar.monthrange(year, month)[1] + 1):
            if day == missing_day:
                continue
            ET.SubElement(sheets, "{" + S + "}sheet", {
                "name": "{0:02}.{1:02}.{2:02}".format(day, month, year % 100),
                "sheetId": str(day), "{" + R + "}id": "rId" + str(day)})
            ET.SubElement(rels, "{" + P + "}Relationship", {
                "Id": "rId" + str(day), "Type": R + "/worksheet",
                "Target": "worksheets/sheet{0}.xml".format(day)})
            tree = ET.Element("{" + S + "}worksheet")
            data = ET.SubElement(tree, "{" + S + "}sheetData")
            values = {address: ("str", value) for address, value in HEADERS.items()}
            values.update(overrides.get(day, {}))
            if header_change and day == 1:
                values["A25"] = ("str", header_change)
            rows = {}
            for address, spec in values.items():
                row_number = int("".join(c for c in address if c.isdigit()))
                if row_number not in rows:
                    rows[row_number] = ET.SubElement(data, "{" + S + "}row", {"r": str(row_number)})
                kind, value = spec[0:2]
                cell = ET.SubElement(rows[row_number], "{" + S + "}c", {"r": address, "t": kind})
                if len(spec) > 2 and spec[2] == "formula":
                    ET.SubElement(cell, "{" + S + "}f").text = '"cached"'
                if kind == "inlineStr":
                    inline = ET.SubElement(cell, "{" + S + "}is")
                    ET.SubElement(inline, "{" + S + "}t").text = value
                else:
                    ET.SubElement(cell, "{" + S + "}v").text = value
            archive.writestr("xl/worksheets/sheet{0}.xml".format(day), ET.tostring(tree))
        archive.writestr("xl/workbook.xml", ET.tostring(workbook))
        archive.writestr("xl/_rels/workbook.xml.rels", ET.tostring(rels))
        if shared is not None:
            strings = ET.Element("{" + S + "}sst")
            for text in shared:
                si = ET.SubElement(strings, "{" + S + "}si")
                ET.SubElement(si, "{" + S + "}t").text = text
            archive.writestr("xl/sharedStrings.xml", ET.tostring(strings))


class ReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.temp.name, "month.xlsx")

    def tearDown(self):
        self.temp.cleanup()

    def test_realistic_routes_and_all_boundaries(self):
        fixture(self.path, {1: {
            "B13": ("str", "Тестов"), "B18": ("str", "Пробов"),
            "B21": ("str", "Примеров"), "B24": ("str", "Учебнов"),
            "B27": ("str", "Макетов"), "D27": ("str", "Хирургия"),
            "B29": ("str", "Образцов"), "D29": ("str", "ОРИТ-2"),
            # Other report sections must not enter the notifications.
            "B33": ("str", "Лишний"), "B59": ("str", "Лишний"),
        }})
        b = read_book(self.path)
        self.assertEqual(len(b["records"]), 6)
        self.assertEqual([r["routes"] for r in b["records"]],
                         [["cardio", "orit"], ["cardio", "orit"], ["cardio"],
                          ["cardio"], ["cardio", "orit"], []])
        self.assertEqual(b["warnings"], [])

    def test_text_encodings(self):
        fixture(self.path, {1: {"B13": ("s", "0"), "B14": ("inlineStr", "Примеров")}},
                shared=["Тестов"])
        b = read_book(self.path)
        self.assertEqual([r["surname"] for r in b["records"]], ["Тестов", "Примеров"])

    def test_no_cached_formula_name_or_source(self):
        fixture(self.path, {1: {"B13": ("str", "Тестов", "formula"),
                                "B27": ("str", "Примеров"),
                                "D27": ("str", "Хирургия", "formula")}})
        b = read_book(self.path)
        self.assertEqual(b["records"], [])
        self.assertEqual([i["kind"] for i in b["issues"]], ["name", "origin"])
        self.assertFalse(any("Тестов" in w or "Примеров" in w for w in b["warnings"]))

    def test_blank_source_waits(self):
        fixture(self.path, {1: {"B27": ("str", "Примеров")}})
        b = read_book(self.path)
        self.assertEqual(b["records"][0]["routes"], [])
        self.assertEqual(b["records"][0]["origin"], "")
        self.assertEqual(b["issues"][0]["kind"], "origin_blank")

    def test_ambiguous_name_waits(self):
        fixture(self.path, {1: {"B13": ("str", "Примеров неизвестная запись")}})
        b = read_book(self.path)
        self.assertEqual(b["records"], [])
        self.assertEqual(b["issues"][0]["kind"], "name")

    def test_invalid_numeric_values_wait(self):
        fixture(self.path, {1: {"B13": ("n", "123"), "B27": ("str", "Примеров"),
                                "D27": ("n", "2")}})
        b = read_book(self.path)
        self.assertEqual(b["records"], [])
        self.assertEqual(len(b["issues"]), 2)

    def test_incomplete_calendar_fails(self):
        fixture(self.path, missing_day=31)
        with self.assertRaises(ReaderError):
            read_book(self.path)

    def test_february_leap_year(self):
        fixture(self.path, year=2028, month=2)
        self.assertEqual(read_book(self.path)["month"], 2)

    def test_layout_drift_fails(self):
        fixture(self.path, header_change="ПЕРЕВЕДЕНЫ ИЗ ПСО")
        with self.assertRaises(ReaderError):
            read_book(self.path)

    def test_corrupt_zip_fails(self):
        with open(self.path, "wb") as f:
            f.write(b"unfinished save")
        with self.assertRaises(ReaderError):
            read_book(self.path)

    def test_names(self):
        for value, expected in [(" Тестов\u00a0", "Тестов"),
                                ("Тестов-Пробов", "Тестов-Пробов"),
                                ("Тестов А. А.", "Тестов"),
                                ("Тестов А.А.", "Тестов"),
                                ("Тестов Александр", "Тестов"),
                                ("Тестов Александр Александрович", "Тестов"),
                                ("де Голль", "де Голль")]:
            self.assertEqual(extract_surname(value), expected)
        for value in ["Тестов 56", "Тестов неизвестная запись", "+", "А."]:
            self.assertIsNone(extract_surname(value))

    def test_orit_variants(self):
        for value in ["ОРИТ", "орит-2", "ОРИТ 1", "Из ОРИТ-2", "ОРИТ–2", "ОРИТ2"]:
            self.assertTrue(is_orit(value))
        for value in ["Хирургия", "Неврология", "КАРО"]:
            self.assertFalse(is_orit(value))


if __name__ == "__main__":
    unittest.main()
