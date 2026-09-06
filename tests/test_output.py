import unittest

from shrawler.output import escape_terminal, neutralize_csv_formula, safe_csv_row


class OutputSafetyTests(unittest.TestCase):
    def test_terminal_controls_are_visible_and_printable_names_remain(self):
        value = "report\x1b[2J\x00\x7f\x80\u202etxt\u2066"

        result = escape_terminal(value)

        self.assertEqual(result, r"report\x1b[2J\x00\x7f\x80\u202etxt\u2066")
        self.assertNotIn("\x1b", result)
        self.assertIn("report", result)
        self.assertIn("txt", result)

    def test_other_format_controls_are_escaped(self):
        self.assertEqual(escape_terminal("a\u200bb"), r"a\u200bb")
        self.assertEqual(escape_terminal("c\u061cd"), r"c\u061cd")

    def test_none_is_rendered_as_empty_text(self):
        self.assertEqual(escape_terminal(None), "")

    def test_csv_formula_prefixes_after_leading_whitespace_or_controls(self):
        for value in (
            "=SUM(A1)",
            "+cmd",
            "-1+1",
            "@A1",
            "  =SUM(A1)",
            "\t@A1",
            "\x00+cmd",
        ):
            with self.subTest(value=value):
                self.assertEqual(neutralize_csv_formula(value), "'" + value)

    def test_csv_regular_values_and_none_are_unchanged(self):
        for value in ("report.txt", "  report.txt", "123", "", None):
            with self.subTest(value=value):
                expected = "" if value is None else value
                self.assertEqual(neutralize_csv_formula(value), expected)

    def test_csv_row_returns_a_safe_presentation_copy(self):
        row = {"name": '=HYPERLINK("https://evil")', "size": 12}

        result = safe_csv_row(row)

        self.assertEqual(result, {"name": '\'=HYPERLINK("https://evil")', "size": "12"})
        self.assertEqual(row["name"], '=HYPERLINK("https://evil")')


if __name__ == "__main__":
    unittest.main()
