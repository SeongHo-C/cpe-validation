from django.db import migrations, models


DECISION_CHOICES = [
    ("CPE_CONFIRMED", "CPE Confirmed"),
    ("OFFICIAL_CPE_MAPPED", "Correct CPE Found"),
    (
        "VERSION_NOT_IN_DICTIONARY",
        "Product Found, Version Not Registered",
    ),
    (
        "NVD_CONFIGURATION_ONLY",
        "Found Only in NVD Configuration",
    ),
    (
        "DIRECT_OFFICIAL_CPE_NOT_CONFIRMED",
        "No Direct CPE Found",
    ),
    ("UNRESOLVED", "Unable to Determine"),
]

DISCREPANCY_TYPES = (
    (
        "PART",
        "Part (Application / OS / Hardware)",
        (
            "The part attribute in the original CPE is incorrect "
            "(application, operating system, or hardware)."
        ),
        10,
        "PART_MISMATCH",
    ),
    (
        "VENDOR",
        "Vendor",
        "The vendor attribute in the original CPE is incorrect.",
        20,
        "VENDOR_MISMATCH",
    ),
    (
        "PRODUCT",
        "Product",
        "The product attribute in the original CPE is incorrect.",
        30,
        "PRODUCT_MISMATCH",
    ),
    (
        "VERSION",
        "Version",
        "The version attribute in the original CPE is incorrect.",
        40,
        "VERSION_MISMATCH",
    ),
    (
        "UPDATE",
        "Update",
        "The update attribute in the original CPE is incorrect.",
        50,
        None,
    ),
    (
        "EDITION",
        "Edition",
        "The edition attribute in the original CPE is incorrect.",
        60,
        None,
    ),
    (
        "LANGUAGE",
        "Language",
        "The language attribute in the original CPE is incorrect.",
        70,
        None,
    ),
    (
        "SW_EDITION",
        "Software Edition",
        "The software edition attribute in the original CPE is incorrect.",
        80,
        None,
    ),
    (
        "TARGET_SW",
        "Target Software",
        "The target software attribute in the original CPE is incorrect.",
        90,
        None,
    ),
    (
        "TARGET_HW",
        "Target Hardware",
        "The target hardware attribute in the original CPE is incorrect.",
        100,
        None,
    ),
    (
        "OTHER",
        "Other",
        "The other attribute in the original CPE is incorrect.",
        110,
        None,
    ),
)

LEGACY_ONLY_TYPES = {
    "DISTRIBUTION_PACKAGE_VERSION_NORMALIZED": {
        "name": "Distribution package version normalized",
        "description": (
            "A distribution or vendor package revision was removed to "
            "recover the upstream product version."
        ),
        "display_order": 50,
    },
    "VERSION_NOT_IN_DICTIONARY": {
        "name": "Version not in Dictionary",
        "description": (
            "The upstream version is confirmed, but an exact official "
            "CPE Name for that version is absent from the Dictionary."
        ),
        "display_order": 60,
    },
}

LEGACY_NAMES = {
    "PART_MISMATCH": "Part mismatch",
    "VENDOR_MISMATCH": "Vendor mismatch",
    "PRODUCT_MISMATCH": "Product mismatch",
    "VERSION_MISMATCH": "Version mismatch",
}


def _copy_relations(source, target):
    for ground_truth in source.ground_truth_records.all().iterator():
        ground_truth.discrepancy_types.add(target)


def seed_classification_taxonomy(apps, schema_editor):
    DiscrepancyType = apps.get_model(
        "sboms",
        "GroundTruthDiscrepancyType",
    )
    database_alias = schema_editor.connection.alias
    manager = DiscrepancyType.objects.using(database_alias)

    for code, name, description, display_order, legacy_code in (
        DISCREPANCY_TYPES
    ):
        target = manager.filter(code=code).first()
        legacy = (
            manager.filter(code=legacy_code).first()
            if legacy_code
            else None
        )
        if target is None and legacy is not None:
            manager.filter(pk=legacy.pk).update(code=code)
            target = manager.get(pk=legacy.pk)
            legacy = None
        if target is None:
            target = manager.create(
                code=code,
                name=name,
                description=description,
                is_active=True,
                display_order=display_order,
            )
        else:
            manager.filter(pk=target.pk).update(
                name=name,
                description=description,
                is_active=True,
                display_order=display_order,
            )
        if legacy is not None and legacy.pk != target.pk:
            _copy_relations(legacy, target)
            manager.filter(pk=legacy.pk).update(is_active=False)

    manager.filter(code__in=LEGACY_ONLY_TYPES).update(
        is_active=False,
    )


def restore_legacy_taxonomy(apps, schema_editor):
    DiscrepancyType = apps.get_model(
        "sboms",
        "GroundTruthDiscrepancyType",
    )
    database_alias = schema_editor.connection.alias
    manager = DiscrepancyType.objects.using(database_alias)

    for code, _name, _description, _order, legacy_code in (
        DISCREPANCY_TYPES
    ):
        if legacy_code is None:
            row = manager.filter(code=code).first()
            if row is not None:
                if row.ground_truth_records.exists():
                    manager.filter(pk=row.pk).update(is_active=False)
                else:
                    row.delete()
            continue
        canonical = manager.filter(code=code).first()
        legacy = manager.filter(code=legacy_code).first()
        if canonical is None:
            continue
        if legacy is not None and legacy.pk != canonical.pk:
            _copy_relations(canonical, legacy)
            manager.filter(pk=canonical.pk).update(is_active=False)
            continue
        manager.filter(pk=canonical.pk).update(
            code=legacy_code,
            name=LEGACY_NAMES[legacy_code],
            is_active=True,
        )

    for code, values in LEGACY_ONLY_TYPES.items():
        manager.filter(code=code).update(
            is_active=True,
            **values,
        )


class Migration(migrations.Migration):

    dependencies = [
        ("sboms", "0010_sourceartifact"),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name="componentcpegroundtruth",
            name="ground_truth_decision_valid",
        ),
        migrations.AlterField(
            model_name="componentcpegroundtruth",
            name="decision",
            field=models.CharField(
                choices=DECISION_CHOICES,
                max_length=64,
            ),
        ),
        migrations.AddConstraint(
            model_name="componentcpegroundtruth",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    decision__in=[code for code, _ in DECISION_CHOICES]
                ),
                name="ground_truth_decision_valid",
            ),
        ),
        migrations.RunPython(
            seed_classification_taxonomy,
            restore_legacy_taxonomy,
        ),
    ]
