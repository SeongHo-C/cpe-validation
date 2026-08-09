from django.db import migrations, models


VERSION_MISMATCH_DESCRIPTION = (
    "The original CPE version differs from the verified product or "
    "upstream version, and the difference cannot be explained solely "
    "by distribution or vendor package version normalization."
)

CANONICAL_ORDER = (
    ("PART_MISMATCH", 10),
    ("PRODUCT_MISMATCH", 20),
    ("VENDOR_MISMATCH", 30),
    ("VERSION_MISMATCH", 40),
    ("DISTRIBUTION_PACKAGE_VERSION_NORMALIZED", 50),
    ("VERSION_NOT_IN_DICTIONARY", 60),
)


def seed_version_mismatch_and_ordering(apps, schema_editor):
    DiscrepancyType = apps.get_model(
        "sboms",
        "GroundTruthDiscrepancyType",
    )
    database_alias = schema_editor.connection.alias
    manager = DiscrepancyType.objects.using(database_alias)

    version_mismatch, _ = manager.update_or_create(
        code="VERSION_MISMATCH",
        defaults={
            "name": "Version mismatch",
            "description": VERSION_MISMATCH_DESCRIPTION,
            "is_active": True,
            "display_order": 40,
        },
    )

    for code, display_order in CANONICAL_ORDER:
        if code == version_mismatch.code:
            continue
        manager.filter(code=code).update(
            display_order=display_order,
        )


class Migration(migrations.Migration):

    dependencies = [
        ("sboms", "0008_ground_truth_decision_discrepancies"),
    ]

    operations = [
        migrations.AddField(
            model_name="groundtruthdiscrepancytype",
            name="display_order",
            field=models.PositiveSmallIntegerField(default=1000),
        ),
        migrations.AlterModelOptions(
            name="groundtruthdiscrepancytype",
            options={"ordering": ("display_order", "id")},
        ),
        migrations.RunPython(
            seed_version_mismatch_and_ordering,
            migrations.RunPython.noop,
        ),
    ]
