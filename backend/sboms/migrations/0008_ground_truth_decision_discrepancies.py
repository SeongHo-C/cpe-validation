from django.db import migrations, models
from django.db.models.functions import Lower


DECISION_CPE_CONFIRMED = "CPE_CONFIRMED"
DECISION_OFFICIAL_CPE_MAPPED = "OFFICIAL_CPE_MAPPED"
DECISION_DIRECT_NOT_CONFIRMED = (
    "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED"
)
DECISION_UNRESOLVED = "UNRESOLVED"

DISCREPANCY_TYPES = (
    (
        "VENDOR_MISMATCH",
        "Vendor mismatch",
        (
            "The vendor in the original CPE differs from the canonical "
            "vendor identity supported by the evidence."
        ),
    ),
    (
        "PRODUCT_MISMATCH",
        "Product mismatch",
        (
            "The product in the original CPE differs from the actual "
            "component or canonical product identity."
        ),
    ),
    (
        "DISTRIBUTION_PACKAGE_VERSION_NORMALIZED",
        "Distribution package version normalized",
        (
            "A distribution or vendor package revision was removed to "
            "recover the upstream product version."
        ),
    ),
    (
        "VERSION_NOT_IN_DICTIONARY",
        "Version not in Dictionary",
        (
            "The upstream version is confirmed, but an exact official "
            "CPE Name for that version is absent from the Dictionary."
        ),
    ),
    (
        "PART_MISMATCH",
        "Part mismatch",
        (
            "The part in the original CPE differs from the actual "
            "product type."
        ),
    ),
)


def _normalized(value):
    return "_".join(
        str(value or "").strip().upper().replace("-", " ").split()
    )


def seed_and_migrate_ground_truth(apps, schema_editor):
    GroundTruth = apps.get_model(
        "sboms",
        "ComponentCpeGroundTruth",
    )
    DiscrepancyType = apps.get_model(
        "sboms",
        "GroundTruthDiscrepancyType",
    )
    database_alias = schema_editor.connection.alias

    discrepancies = {}
    for code, name, description in DISCREPANCY_TYPES:
        discrepancy, _ = DiscrepancyType.objects.using(
            database_alias
        ).update_or_create(
            code=code,
            defaults={
                "name": name,
                "description": description,
                "is_active": True,
            },
        )
        discrepancies[code] = discrepancy

    discrepancy_mappings = {
        "VENDOR_CORRECTED": "VENDOR_MISMATCH",
        "VENDOR_MISMATCH": "VENDOR_MISMATCH",
        "PRODUCT_CORRECTED": "PRODUCT_MISMATCH",
        "PRODUCT_MISMATCH": "PRODUCT_MISMATCH",
        (
            "DISTRIBUTION_PACKAGE_VERSION_NORMALIZED"
        ): "DISTRIBUTION_PACKAGE_VERSION_NORMALIZED",
        (
            "DISTRIBUTION_PACKAGE_REVISION_NORMALIZED"
        ): "DISTRIBUTION_PACKAGE_VERSION_NORMALIZED",
        "VERSION_NOT_IN_DICTIONARY": "VERSION_NOT_IN_DICTIONARY",
        "PART_CORRECTED": "PART_MISMATCH",
        "PART_MISMATCH": "PART_MISMATCH",
    }
    outcome_mappings = {
        "ORIGINAL_OFFICIAL_CONFIRMED": DECISION_CPE_CONFIRMED,
        "CORRECTED_TO_DICTIONARY": DECISION_OFFICIAL_CPE_MAPPED,
        "MANUAL_FROM_OFFICIAL_FAMILY": DECISION_OFFICIAL_CPE_MAPPED,
        (
            "DIRECT_OFFICIAL_NOT_CONFIRMED"
        ): DECISION_DIRECT_NOT_CONFIRMED,
        "UNRESOLVED": DECISION_UNRESOLVED,
    }

    queryset = GroundTruth.objects.using(database_alias).prefetch_related(
        "correction_types"
    )
    for ground_truth in queryset.iterator(chunk_size=200):
        legacy_types = list(ground_truth.correction_types.all())
        normalized_legacy_values = {
            _normalized(value)
            for correction_type in legacy_types
            for value in (correction_type.code, correction_type.name)
        }
        decision = outcome_mappings.get(
            ground_truth.resolution_outcome,
            DECISION_UNRESOLVED,
        )
        if "CPE_CONFIRMED" in normalized_legacy_values:
            decision = DECISION_CPE_CONFIRMED
        elif "UNRESOLVED" in normalized_legacy_values:
            decision = DECISION_UNRESOLVED
        elif (
            "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED"
            in normalized_legacy_values
        ):
            decision = DECISION_DIRECT_NOT_CONFIRMED
        elif normalized_legacy_values.intersection(
            {
                "MAPPED_TO_OFFICIAL_PRODUCT_CPE",
                "DISTRIBUTION_PACKAGE_VERSION_NORMALIZED",
                "DISTRIBUTION_PACKAGE_REVISION_NORMALIZED",
            }
        ):
            decision = DECISION_OFFICIAL_CPE_MAPPED

        ground_truth.decision = decision
        ground_truth.save(update_fields=("decision",))

        discrepancy_codes = {
            discrepancy_mappings[value]
            for value in normalized_legacy_values
            if value in discrepancy_mappings
        }
        if discrepancy_codes:
            ground_truth.discrepancy_types.add(
                *(
                    discrepancies[code]
                    for code in sorted(discrepancy_codes)
                )
            )


class Migration(migrations.Migration):

    dependencies = [
        ("sboms", "0007_sbomdocument_uploaded_file"),
    ]

    operations = [
        migrations.CreateModel(
            name="GroundTruthDiscrepancyType",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "code",
                    models.CharField(max_length=128, unique=True),
                ),
                ("name", models.CharField(max_length=255)),
                ("description", models.TextField(blank=True)),
                ("is_active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ("name", "id")},
        ),
        migrations.AddConstraint(
            model_name="groundtruthdiscrepancytype",
            constraint=models.UniqueConstraint(
                Lower("name"),
                name="unique_gt_discrepancy_type_name_ci",
            ),
        ),
        migrations.AddField(
            model_name="componentcpegroundtruth",
            name="decision",
            field=models.CharField(
                blank=True,
                choices=[
                    (DECISION_CPE_CONFIRMED, "CPE Confirmed"),
                    (
                        DECISION_OFFICIAL_CPE_MAPPED,
                        "Official CPE mapped",
                    ),
                    (
                        DECISION_DIRECT_NOT_CONFIRMED,
                        "Direct official CPE not confirmed",
                    ),
                    (DECISION_UNRESOLVED, "Unresolved"),
                ],
                default="",
                max_length=64,
            ),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="componentcpegroundtruth",
            name="discrepancy_types",
            field=models.ManyToManyField(
                blank=True,
                related_name="ground_truth_records",
                to="sboms.groundtruthdiscrepancytype",
            ),
        ),
        migrations.AlterField(
            model_name="componentcpegroundtruth",
            name="resolution_outcome",
            field=models.CharField(
                choices=[
                    (
                        "ORIGINAL_OFFICIAL_CONFIRMED",
                        "Original CPE confirmed",
                    ),
                    (
                        "CORRECTED_TO_DICTIONARY",
                        "Corrected to official CPE",
                    ),
                    (
                        "MANUAL_FROM_OFFICIAL_FAMILY",
                        "Manual CPE from official family",
                    ),
                    (
                        "DIRECT_OFFICIAL_NOT_CONFIRMED",
                        "Direct official CPE not confirmed",
                    ),
                    ("UNRESOLVED", "Unresolved"),
                ],
                editable=False,
                max_length=64,
            ),
        ),
        migrations.RunPython(
            seed_and_migrate_ground_truth,
            migrations.RunPython.noop,
        ),
        migrations.AlterField(
            model_name="componentcpegroundtruth",
            name="decision",
            field=models.CharField(
                choices=[
                    (DECISION_CPE_CONFIRMED, "CPE Confirmed"),
                    (
                        DECISION_OFFICIAL_CPE_MAPPED,
                        "Official CPE mapped",
                    ),
                    (
                        DECISION_DIRECT_NOT_CONFIRMED,
                        "Direct official CPE not confirmed",
                    ),
                    (DECISION_UNRESOLVED, "Unresolved"),
                ],
                max_length=64,
            ),
        ),
        migrations.AddConstraint(
            model_name="componentcpegroundtruth",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    decision__in=[
                        DECISION_CPE_CONFIRMED,
                        DECISION_OFFICIAL_CPE_MAPPED,
                        DECISION_DIRECT_NOT_CONFIRMED,
                        DECISION_UNRESOLVED,
                    ]
                ),
                name="ground_truth_decision_valid",
            ),
        ),
    ]
