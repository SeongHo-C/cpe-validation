from django.test import SimpleTestCase

from nvd_cve.cpe_dictionary_coverage import (
    EXACT_ABSENT_TUPLE_ABSENT,
    EXACT_ABSENT_TUPLE_PRESENT,
    EXACT_PRESENT,
    CriteriaAggregate,
    DictionaryTupleStats,
    classify_criteria_expression,
)


def cpe(
    *,
    part: str = "a",
    vendor: str = "vendor",
    product: str = "product",
    version: str = "1.0",
) -> str:
    return (
        f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    )


def aggregate(
    criteria: str,
    *,
    true_count: int = 1,
    false_count: int = 0,
    has_range: bool = False,
    has_no_range: bool = True,
) -> CriteriaAggregate:
    return CriteriaAggregate(
        criteria=criteria,
        occurrence_count=true_count + false_count,
        distinct_cve_count=1,
        vulnerable_true_count=true_count,
        vulnerable_false_count=false_count,
        has_range=has_range,
        has_no_range=has_no_range,
    )


class CriteriaCoverageFixtureTests(SimpleTestCase):
    databases = set()

    def setUp(self) -> None:
        self.active_tuple = DictionaryTupleStats(
            dictionary_count=2,
            active_count=2,
            deprecated_count=0,
        )
        self.mixed_tuple = DictionaryTupleStats(
            dictionary_count=3,
            active_count=2,
            deprecated_count=1,
        )

    def classify(
        self,
        value: CriteriaAggregate,
        *,
        exact_deprecated: bool | None = None,
        tuples=None,
    ):
        return classify_criteria_expression(
            value,
            exact_deprecated=exact_deprecated,
            dictionary_tuples=(tuples if tuples is not None else {}),
        )[0]

    def test_three_coverage_classes_and_concrete_version(self) -> None:
        # 1. exact exists; 4. concrete version.
        exact = self.classify(
            aggregate(cpe()),
            exact_deprecated=False,
            tuples={("a", "vendor", "product"): self.active_tuple},
        )
        self.assertEqual(exact["final_coverage_class"], EXACT_PRESENT)
        self.assertEqual(exact["exact_dictionary_status"], "ACTIVE")
        self.assertEqual(exact["criteria_form"], "CONCRETE")

        # 2. exact absent, same part/vendor/product exists.
        same_tuple = self.classify(
            aggregate(cpe(version="9.9")),
            tuples={("a", "vendor", "product"): self.active_tuple},
        )
        self.assertEqual(
            same_tuple["final_coverage_class"],
            EXACT_ABSENT_TUPLE_PRESENT,
        )

        # 3. exact absent and product tuple absent.
        absent = self.classify(aggregate(cpe(vendor="missing")))
        self.assertEqual(
            absent["final_coverage_class"],
            EXACT_ABSENT_TUPLE_ABSENT,
        )

    def test_wildcard_range_patterns_are_not_collapsed(self) -> None:
        wildcard = cpe(version="*")

        # 5. wildcard no-range.
        no_range = self.classify(aggregate(wildcard))
        self.assertEqual(no_range["criteria_form"], "WILDCARD_NO_RANGE")
        self.assertEqual(no_range["range_usage_pattern"], "NO_RANGE_ONLY")

        # 6. wildcard with-range.
        with_range = self.classify(
            aggregate(
                wildcard,
                has_range=True,
                has_no_range=False,
            )
        )
        self.assertEqual(with_range["criteria_form"], "WILDCARD_RANGE")
        self.assertEqual(with_range["range_usage_pattern"], "RANGE_ONLY")

        # 7. the same criteria has range and no-range occurrences.
        both = self.classify(
            aggregate(wildcard, has_range=True, has_no_range=True)
        )
        self.assertEqual(both["criteria_form"], "WILDCARD_BOTH")
        self.assertEqual(
            both["range_usage_pattern"],
            "BOTH_RANGE_AND_NO_RANGE",
        )

    def test_vulnerable_usage_is_an_independent_attribute(self) -> None:
        criteria = cpe()

        # 8. true-only.
        true_only = self.classify(aggregate(criteria, true_count=3))
        self.assertEqual(true_only["vulnerable_usage_group"], "TRUE_ONLY")

        # 9. false-only.
        false_only = self.classify(
            aggregate(criteria, true_count=0, false_count=2)
        )
        self.assertEqual(
            false_only["vulnerable_usage_group"],
            "FALSE_ONLY",
        )

        # 10. true and false.
        both = self.classify(
            aggregate(criteria, true_count=2, false_count=4)
        )
        self.assertEqual(
            both["vulnerable_usage_group"],
            "BOTH_TRUE_AND_FALSE",
        )

    def test_deprecated_mixed_tuple_and_escaped_fields(self) -> None:
        # 11. deprecated exact CPE.
        deprecated = self.classify(
            aggregate(cpe()),
            exact_deprecated=True,
            tuples={("a", "vendor", "product"): self.mixed_tuple},
        )
        self.assertEqual(deprecated["final_coverage_class"], EXACT_PRESENT)
        self.assertEqual(
            deprecated["exact_dictionary_status"],
            "DEPRECATED",
        )

        # 12. a tuple contains both active and deprecated Dictionary CPEs.
        mixed = self.classify(
            aggregate(cpe(version="*")),
            tuples={("a", "vendor", "product"): self.mixed_tuple},
        )
        self.assertEqual(
            mixed["tuple_status_composition"],
            "MIXED_ACTIVE_AND_DEPRECATED",
        )
        self.assertEqual(mixed["tuple_active_count"], 2)
        self.assertEqual(mixed["tuple_deprecated_count"], 1)

        # 13. escaped raw fields retain exact parser output for tuple lookup.
        escaped = cpe(vendor=r"ven\:dor", product=r"pro\:duct", version="*")
        escaped_row = self.classify(
            aggregate(escaped),
            tuples={("a", r"ven\:dor", r"pro\:duct"): self.active_tuple},
        )
        self.assertEqual(
            escaped_row["final_coverage_class"],
            EXACT_ABSENT_TUPLE_PRESENT,
        )
        self.assertEqual(escaped_row["vendor"], r"ven\:dor")
        self.assertEqual(escaped_row["product"], r"pro\:duct")
