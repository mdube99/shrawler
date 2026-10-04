"""Combined rule/Jev scoring: normalization, blending, and SQL agreement."""

import unittest

from shrawler.triage.scoring import (
    COVERAGE_BOTH,
    COVERAGE_JEV,
    COVERAGE_NONE,
    COVERAGE_RULES,
    RATING_FULL,
    ScoringConfig,
    combine_priority,
    combined_sql,
)


class CombinePriorityTests(unittest.TestCase):
    def test_neither_available_is_unavailable(self) -> None:
        self.assertEqual(
            combine_priority(None, None, rating_available=False, jev_available=False),
            (None, COVERAGE_NONE),
        )

    def test_rules_only_fills_full_scale(self) -> None:
        # No Jev run selected: the rule rating alone spans 0-100.
        self.assertEqual(
            combine_priority(80, None, rating_available=True, jev_available=False),
            (100, COVERAGE_RULES),
        )
        self.assertEqual(
            combine_priority(0, None, rating_available=True, jev_available=False),
            (0, COVERAGE_RULES),
        )

    def test_jev_only_fills_full_scale(self) -> None:
        self.assertEqual(
            combine_priority(None, 4, rating_available=False, jev_available=True),
            (100, COVERAGE_JEV),
        )
        self.assertEqual(
            combine_priority(None, 2, rating_available=False, jev_available=True),
            (50, COVERAGE_JEV),
        )

    def test_equal_weight_agreement_and_conflict(self) -> None:
        # id_rsa: rule 45 (0.5625) and Jev 4 (1.0) -> 78.
        self.assertEqual(
            combine_priority(45, 4, rating_available=True, jev_available=True),
            (78, COVERAGE_BOTH),
        )
        # rules-missed credential: rule 0, Jev 4 -> 50.
        self.assertEqual(
            combine_priority(0, 4, rating_available=True, jev_available=True),
            (50, COVERAGE_BOTH),
        )
        # ntds.dit: rule 80, Jev 0 -> 50.
        self.assertEqual(
            combine_priority(80, 0, rating_available=True, jev_available=True),
            (50, COVERAGE_BOTH),
        )

    def test_missing_file_result_counts_as_zero_not_renormalized(self) -> None:
        # Both runs selected, but this file has no Jev answer: the Jev weight
        # stays in the denominator, so a max rule rating is 50, not 100.
        self.assertEqual(
            combine_priority(80, None, rating_available=True, jev_available=True),
            (50, COVERAGE_RULES),
        )

    def test_rating_saturates_above_the_cap(self) -> None:
        self.assertEqual(
            combine_priority(200, None, rating_available=True, jev_available=False),
            (100, COVERAGE_RULES),
        )

    def test_jev_clamped_to_the_zero_to_four_scale(self) -> None:
        self.assertEqual(
            combine_priority(None, 9, rating_available=False, jev_available=True),
            (100, COVERAGE_JEV),
        )
        self.assertEqual(
            combine_priority(None, -3, rating_available=False, jev_available=True),
            (0, COVERAGE_JEV),
        )

    def test_custom_weights_and_cap(self) -> None:
        config = ScoringConfig(rating_full=100, rating_weight=1.0, jev_weight=3.0)
        # Rule 50 -> 0.5 at weight 1; Jev 4 -> 1.0 at weight 3.
        # (1*0.5 + 3*1.0) / 4 = 0.875 -> 88.
        self.assertEqual(
            combine_priority(
                50, 4, rating_available=True, jev_available=True, config=config
            ),
            (88, COVERAGE_BOTH),
        )


class ScoringConfigTests(unittest.TestCase):
    def test_defaults(self) -> None:
        config = ScoringConfig()
        self.assertEqual(config.rating_full, RATING_FULL)
        self.assertEqual(config.rating_weight, 0.5)
        self.assertEqual(config.jev_weight, 0.5)

    def test_rejects_unknown_and_invalid_values(self) -> None:
        for mapping in (
            {"bogus": 1},
            {"rating_full": 0},
            {"rating_full": -1},
            {"rating_full": "80"},
            {"rating_weight": 0},
            {"jev_weight": -0.5},
            {"rating_weight": True},
            {"rating_weight": "0.5"},
        ):
            with self.subTest(mapping=mapping):
                with self.assertRaises(ValueError):
                    ScoringConfig.from_mapping(mapping)

    def test_accepts_partial_overrides(self) -> None:
        config = ScoringConfig.from_mapping({"rating_weight": 2, "jev_weight": 1})
        self.assertEqual(config.rating_weight, 2.0)
        self.assertEqual(config.jev_weight, 1.0)


class CombinedSqlTests(unittest.TestCase):
    def test_no_components_produces_no_expression(self) -> None:
        self.assertIsNone(
            combined_sql("x", "y", rating_available=False, jev_available=False)
        )

    def test_expression_mirrors_python_for_rules_only(self) -> None:
        import sqlite3

        sql = combined_sql("40", "NULL", rating_available=True, jev_available=False)
        self.assertIsNotNone(sql)
        value = sqlite3.connect(":memory:").execute(
            "SELECT ROUND(" + sql + ")"  # type: ignore[operator]
        ).fetchone()[0]
        expected, _ = combine_priority(
            40, None, rating_available=True, jev_available=False
        )
        self.assertEqual(int(value), expected)

    def test_expression_mirrors_python_when_both_available(self) -> None:
        import sqlite3

        sql = combined_sql("45", "'4'", rating_available=True, jev_available=True)
        value = sqlite3.connect(":memory:").execute(
            "SELECT ROUND(" + sql + ")"  # type: ignore[operator]
        ).fetchone()[0]
        expected, _ = combine_priority(
            45, 4, rating_available=True, jev_available=True
        )
        self.assertEqual(int(value), expected)

    def test_expression_treats_null_jev_as_zero(self) -> None:
        import sqlite3

        sql = combined_sql(
            "80", "NULL", rating_available=True, jev_available=True
        )
        value = sqlite3.connect(":memory:").execute(
            "SELECT ROUND(" + sql + ")"  # type: ignore[operator]
        ).fetchone()[0]
        self.assertEqual(int(value), 50)


if __name__ == "__main__":
    unittest.main()
