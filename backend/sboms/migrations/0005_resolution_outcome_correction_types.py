from django.db import migrations, models
from django.db.models.functions import Lower


OUTCOME_ORIGINAL = "ORIGINAL_OFFICIAL_CONFIRMED"
OUTCOME_CORRECTED = "CORRECTED_TO_DICTIONARY"
OUTCOME_MANUAL = "MANUAL_FROM_OFFICIAL_FAMILY"
OUTCOME_DIRECT = "DIRECT_OFFICIAL_NOT_CONFIRMED"

CORRECTION_TYPES = (
    (
        "vendor_corrected",
        "Vendor corrected",
        (
            "The vendor field in the SBOM CPE was changed to the "
            "canonical vendor used by the Official CPE Dictionary."
        ),
    ),
    (
        "product_corrected",
        "Product corrected",
        (
            "The product field in the SBOM CPE was changed to the "
            "canonical product name used by the Official CPE "
            "Dictionary."
        ),
    ),
    (
        "distribution_package_version_normalized",
        "Distribution package version normalized",
        (
            "Distribution-specific version elements such as an "
            "epoch, package revision, build revision, or Alpine "
            "revision were removed to recover the upstream software "
            "version."
        ),
    ),
    (
        "mapped_to_parent_product",
        "Mapped to parent product",
        (
            "The SBOM component represented a binary or subpackage "
            "and was mapped to the CPE of its confirmed parent or "
            "source product."
        ),
    ),
    (
        "deprecated_cpe_redirected",
        "Deprecated CPE redirected to active CPE",
        (
            "A deprecated Official CPE identity was redirected to "
            "its active canonical CPE."
        ),
    ),
)


def reset_legacy_ground_truth_and_seed_corrections(
    apps,
    schema_editor,
):
    """
    Reset pilot-only annotations and seed the replacement taxonomy.

    This migration intentionally does not infer a reversible mapping
    between the legacy single Decision Type and the new independent
    Outcome/Correction axes. The repository was still in its pilot
    stage when this reset was approved.
    """

    GroundTruth = apps.get_model(
        "sboms",
        "ComponentCpeGroundTruth",
    )
    CorrectionType = apps.get_model(
        "sboms",
        "GroundTruthCorrectionType",
    )
    database_alias = schema_editor.connection.alias

    GroundTruth.objects.using(database_alias).all().delete()
    for code, name, description in CORRECTION_TYPES:
        CorrectionType.objects.using(
            database_alias
        ).update_or_create(
            code=code,
            defaults={
                "name": name,
                "description": description,
                "is_active": True,
            },
        )


class Migration(migrations.Migration):
    """
    Irreversible development reset of the legacy Ground Truth taxonomy.

    Reconstructing a legacy single Decision Type from the new
    many-valued correction relation is ambiguous. RunPython therefore
    has no reverse callable; Django will refuse to unapply this
    migration instead of producing an inaccurate reconstruction.
    """

    dependencies = [
        ("sboms", "0004_groundtruthdecisiontype"),
    ]

    operations = [
        migrations.CreateModel(
            name="GroundTruthCorrectionType",
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
                (
                    "created_at",
                    models.DateTimeField(auto_now_add=True),
                ),
                (
                    "updated_at",
                    models.DateTimeField(auto_now=True),
                ),
            ],
            options={"ordering": ("name", "id")},
        ),
        migrations.AddConstraint(
            model_name="groundtruthcorrectiontype",
            constraint=models.UniqueConstraint(
                Lower("name"),
                name=(
                    "unique_ground_truth_correction_type_name_ci"
                ),
            ),
        ),
        migrations.AddField(
            model_name="componentcpegroundtruth",
            name="resolution_outcome",
            field=models.CharField(
                blank=True,
                choices=[
                    (
                        OUTCOME_ORIGINAL,
                        "Original CPE confirmed",
                    ),
                    (
                        OUTCOME_CORRECTED,
                        "Corrected to official CPE",
                    ),
                    (
                        OUTCOME_MANUAL,
                        "Manual CPE from official family",
                    ),
                    (
                        OUTCOME_DIRECT,
                        "Direct official CPE not confirmed",
                    ),
                ],
                editable=False,
                max_length=64,
            ),
        ),
        migrations.AddField(
            model_name="componentcpegroundtruth",
            name="correction_types",
            field=models.ManyToManyField(
                blank=True,
                related_name="ground_truth_records",
                to="sboms.groundtruthcorrectiontype",
            ),
        ),
        migrations.RunPython(
            reset_legacy_ground_truth_and_seed_corrections,
        ),
        migrations.RemoveField(
            model_name="componentcpegroundtruth",
            name="decision_type",
        ),
        migrations.DeleteModel(
            name="GroundTruthDecisionType",
        ),
        migrations.AlterField(
            model_name="componentcpegroundtruth",
            name="resolution_outcome",
            field=models.CharField(
                choices=[
                    (
                        OUTCOME_ORIGINAL,
                        "Original CPE confirmed",
                    ),
                    (
                        OUTCOME_CORRECTED,
                        "Corrected to official CPE",
                    ),
                    (
                        OUTCOME_MANUAL,
                        "Manual CPE from official family",
                    ),
                    (
                        OUTCOME_DIRECT,
                        "Direct official CPE not confirmed",
                    ),
                ],
                editable=False,
                max_length=64,
            ),
        ),
    ]
