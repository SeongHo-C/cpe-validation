from django.test import SimpleTestCase

from cpe.cpe23_canonical import (
    canonicalize_cpe23,
    compare_cpe23_attributes,
    parse_cpe23,
)
from cpe_dictionary.wpa_supplicant_prerelease_policy import (
    CANDIDATES,
    classify_prerelease_attributes,
)


class WpaSupplicantPrereleasePolicyTests(SimpleTestCase):
    def test_all_candidates_are_canonical_and_have_expected_attributes(self) -> None:
        expected = {
            "A": ("2.11", "*"),
            "B": ("2.11", "devel"),
            "C": ("2.11-devel", "*"),
        }
        for candidate in CANDIDATES:
            with self.subTest(candidate=candidate["candidate"]):
                self.assertEqual(
                    canonicalize_cpe23(candidate["cpe"]),
                    candidate["cpe"],
                )
                parsed = parse_cpe23(candidate["cpe"])
                self.assertIsNotNone(parsed.name)
                self.assertEqual(
                    (
                        parsed.name.attribute("version").canonical,
                        parsed.name.attribute("update").canonical,
                    ),
                    expected[candidate["candidate"]],
                )

    def test_candidate_b_is_the_only_recommendation(self) -> None:
        recommended = [
            candidate for candidate in CANDIDATES
            if candidate["decision"] == "RECOMMENDED"
        ]
        self.assertEqual(len(recommended), 1)
        self.assertEqual(recommended[0]["candidate"], "B")

    def test_candidate_b_changes_only_update_from_current_cpe(self) -> None:
        current = next(
            candidate["cpe"]
            for candidate in CANDIDATES
            if candidate["candidate"] == "A"
        )
        recommended = next(
            candidate["cpe"]
            for candidate in CANDIDATES
            if candidate["candidate"] == "B"
        )
        self.assertEqual(
            compare_cpe23_attributes(current, recommended),
            ("update",),
        )

    def test_family_pre_tokens_are_classified_in_update(self) -> None:
        self.assertEqual(
            classify_prerelease_attributes("0.2.3", "pre1"),
            {
                "attribute_pattern": "EXPLICIT_PRERELEASE_UPDATE",
                "prerelease_token_location": "update",
                "prerelease_token": "pre1",
            },
        )
        self.assertEqual(
            classify_prerelease_attributes("0.3.0", "pre4"),
            {
                "attribute_pattern": "EXPLICIT_PRERELEASE_UPDATE",
                "prerelease_token_location": "update",
                "prerelease_token": "pre4",
            },
        )

    def test_devel_in_atomic_version_is_detected_for_policy_review(self) -> None:
        self.assertEqual(
            classify_prerelease_attributes("2.11-devel", "*"),
            {
                "attribute_pattern": "PRERELEASE_TOKEN_IN_VERSION",
                "prerelease_token_location": "version",
                "prerelease_token": "devel",
            },
        )

    def test_hyphen_alone_does_not_trigger_prerelease_normalization(self) -> None:
        self.assertEqual(
            classify_prerelease_attributes("2.0-16", "*")[
                "attribute_pattern"
            ],
            "GENERIC_UPDATE_ANY",
        )
