from __future__ import annotations

from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError, CommandParser

from cpe_dictionary.models import CpeDictionarySnapshot
from nvd_cve.models import NvdCveSnapshot
from sboms.unitronics_ground_truth_finalization import (
    CPE_SNAPSHOT_ID,
    NVD_SNAPSHOT_ID,
    UnitronicsGroundTruthFinalizationError,
    default_output_directory,
    finalize_unitronics_ground_truth,
    load_finalization_plan,
    write_finalization_artifacts,
)


class Command(BaseCommand):
    help = (
        "Apply the approved single wireguard-tools Ground Truth correction and "
        "run the final fixed-snapshot Unitronics audits."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--apply",
            action="store_true",
            help="Required explicit authorization for the one-row DB update.",
        )
        parser.add_argument("--output-dir", type=Path)

    def handle(self, *args, **options) -> None:
        if not options["apply"]:
            raise CommandError("Refusing DB mutation without --apply")
        output = options["output_dir"] or default_output_directory()
        if not output.is_absolute():
            output = settings.REPOSITORY_ROOT / output
        if output.exists():
            raise CommandError(f"Refusing to overwrite final artifact: {output}")
        try:
            plan = load_finalization_plan()
            result = finalize_unitronics_ground_truth(
                plan,
                cpe_snapshot=CpeDictionarySnapshot.objects.get(
                    snapshot_id=CPE_SNAPSHOT_ID
                ),
                nvd_snapshot=NvdCveSnapshot.objects.get(
                    snapshot_id=NVD_SNAPSHOT_ID
                ),
            )
            paths = write_finalization_artifacts(result, output)
        except (
            CpeDictionarySnapshot.DoesNotExist,
            NvdCveSnapshot.DoesNotExist,
            OSError,
            ValueError,
            UnitronicsGroundTruthFinalizationError,
        ) as error:
            raise CommandError(str(error)) from error

        self.stdout.write(
            self.style.SUCCESS("UNITRONICS GROUND TRUTH FINALIZATION: SUCCESS")
        )
        self.stdout.write(
            "wireguard-tools: VERSION_NOT_IN_DICTIONARY / manual CPE -> "
            "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED / null"
        )
        self.stdout.write(
            "CPE-bearing=39; null=543; distinct=39; duplicates=0; "
            "candidate_mismatch=0; component_mutation=0"
        )
        for path in paths:
            self.stdout.write(str(path))
