import csv
from pathlib import Path
from tempfile import TemporaryDirectory

from django.test import SimpleTestCase

from cpe_analysis.rq2_runner import (
    CANDIDATE_UNIVERSE_RELATIVE_PATH,
    GROUND_TRUTH_RELATIVE_PATH,
    load_candidate_families,
    load_ground_truth_queries,
)


class RQ2CanonicalInputLoaderTests(SimpleTestCase):
    def setUp(self) -> None:
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_final_input_paths_are_repository_relative(self) -> None:
        self.assertEqual(
            GROUND_TRUTH_RELATIVE_PATH,
            Path("research/ground_truth/ground_truth.csv"),
        )
        self.assertEqual(
            CANDIDATE_UNIVERSE_RELATIVE_PATH,
            Path("data/cpe_candidate_universe/candidate_families.csv"),
        )
        self.assertNotIn("/tmp", str(GROUND_TRUTH_RELATIVE_PATH))
        self.assertNotIn("/tmp", str(CANDIDATE_UNIVERSE_RELATIVE_PATH))

    def test_loaders_use_csv_files_without_manifests(self) -> None:
        candidate_path = self.root / "candidate_families.csv"
        with candidate_path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(
                stream,
                fieldnames=(
                    "family_id",
                    "part",
                    "vendor",
                    "product",
                    "source",
                    "searchable",
                ),
            )
            writer.writeheader()
            writer.writerow(
                {
                    "family_id": "target",
                    "part": "a",
                    "vendor": "haxx",
                    "product": "curl",
                    "source": "ACTIVE_DICTIONARY",
                    "searchable": "True",
                }
            )
            writer.writerow(
                {
                    "family_id": "excluded",
                    "part": "a",
                    "vendor": "example",
                    "product": "*",
                    "source": "NVD_CONFIGURATION_ONLY",
                    "searchable": "False",
                }
            )

        ground_truth_path = self.root / "ground_truth.csv"
        with ground_truth_path.open(
            "w", newline="", encoding="utf-8"
        ) as stream:
            writer = csv.DictWriter(
                stream,
                fieldnames=(
                    "firmware_vendor",
                    "firmware_product",
                    "firmware_version",
                    "sbom_document_id",
                    "component_id",
                    "component_name",
                    "ground_truth_cpe",
                    "validation_result",
                    "cpe_present",
                ),
            )
            writer.writeheader()
            writer.writerow(
                {
                    "firmware_vendor": "Teltonika",
                    "firmware_product": "RUT986",
                    "firmware_version": "00.07.24.2",
                    "sbom_document_id": "1",
                    "component_id": "2",
                    "component_name": "curl",
                    "ground_truth_cpe": (
                        "cpe:2.3:a:haxx:curl:8.19.0:*:*:*:*:*:*:*"
                    ),
                    "validation_result": "OFFICIAL_CPE_MAPPED",
                    "cpe_present": "true",
                }
            )

        candidates = load_candidate_families(
            candidate_path,
            enforce_fixed_contract=False,
        )
        queries = load_ground_truth_queries(
            ground_truth_path,
            candidates,
            enforce_fixed_contract=False,
        )

        self.assertEqual(len(candidates.all_families), 2)
        self.assertEqual(len(candidates.searchable_families), 1)
        self.assertEqual(len(queries), 1)
        self.assertEqual(queries[0].retrieval_query.gt_family_id, "target")
        self.assertEqual(queries[0].retrieval_query.query_text, "curl")
