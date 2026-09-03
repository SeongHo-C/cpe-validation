from django.test import SimpleTestCase

from cpe_analysis.candidate_universe_generator import (
    candidate_source_map,
    family_id,
    searchability,
)


class CandidateUniverseGeneratorContractTests(SimpleTestCase):
    def test_family_id_matches_frozen_contract(self) -> None:
        family = ("a", ".bbsoftware", "bb_flashback")

        self.assertEqual(
            family_id(family),
            "ffbfe1e5139ea6c297c5d2e4dd060dce4f9f4b57ea575f5a42ff4fc2937cccac",
        )

    def test_source_map_excludes_deprecated_only_dictionary_family(self) -> None:
        active = {("a", "active", "product")}
        deprecated_only = ("a", "deprecated", "product")
        configuration_only = ("a", "configuration", "product")
        deprecated = {
            ("a", "active", "product"),
            deprecated_only,
        }
        nvd = {
            ("a", "active", "product"),
            deprecated_only,
            configuration_only,
        }

        sources, configuration_families = candidate_source_map(
            active,
            deprecated,
            nvd,
        )

        self.assertEqual(
            sources,
            {
                ("a", "active", "product"): "ACTIVE_DICTIONARY",
                configuration_only: "NVD_CONFIGURATION_ONLY",
            },
        )
        self.assertEqual(configuration_families, {configuration_only})
        self.assertNotIn(deprecated_only, sources)

    def test_searchability_matches_frozen_policy(self) -> None:
        self.assertEqual(
            searchability(("a", "vendor", "product")),
            (True, "SEARCHABLE"),
        )
        self.assertEqual(
            searchability(("a", "vendor", "*")),
            (False, "NON_SEARCHABLE_WILDCARD"),
        )
        self.assertEqual(
            searchability(("a", "-", "product")),
            (False, "NON_SEARCHABLE_NA"),
        )
