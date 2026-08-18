from __future__ import annotations

import hashlib
import io
import stat
import tarfile
import tempfile
import zipfile
from io import StringIO
from pathlib import Path

from django.core.files.base import ContentFile
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings

from sboms.models import SBOMDocument, SourceArtifact
from sboms.source_extraction import EXTRACTION_MARKER_FILENAME


class SourceArtifactExtractionCommandTests(TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.media_root = Path(self.temporary_directory.name)
        self.media_settings = override_settings(MEDIA_ROOT=self.media_root)
        self.media_settings.enable()

    def tearDown(self) -> None:
        self.media_settings.disable()
        self.temporary_directory.cleanup()

    @staticmethod
    def zip_bytes(entries: dict[str, bytes]) -> bytes:
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            for name, content in entries.items():
                archive.writestr(name, content)
        return output.getvalue()

    @staticmethod
    def tar_bytes(
        entries: dict[str, bytes],
        *,
        mode: str = "w:gz",
    ) -> bytes:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode=mode) as archive:
            for name, content in entries.items():
                member = tarfile.TarInfo(name)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
        return output.getvalue()

    @staticmethod
    def tar_with_links(
        *,
        files: dict[str, bytes] | None = None,
        directories: tuple[str, ...] = (),
        symlinks: tuple[tuple[str, str], ...] = (),
        hardlinks: tuple[tuple[str, str], ...] = (),
    ) -> bytes:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            for name, target in symlinks:
                member = tarfile.TarInfo(name)
                member.type = tarfile.SYMTYPE
                member.linkname = target
                archive.addfile(member)
            for name, target in hardlinks:
                member = tarfile.TarInfo(name)
                member.type = tarfile.LNKTYPE
                member.linkname = target
                archive.addfile(member)
            for name in directories:
                member = tarfile.TarInfo(name)
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            for name, content in (files or {}).items():
                member = tarfile.TarInfo(name)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
        return output.getvalue()

    @staticmethod
    def zip_with_symlinks(
        *,
        files: dict[str, bytes] | None = None,
        directories: tuple[str, ...] = (),
        symlinks: tuple[tuple[str, str], ...] = (),
    ) -> bytes:
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            for name, target in symlinks:
                member = zipfile.ZipInfo(name)
                member.create_system = 3
                member.external_attr = (
                    stat.S_IFLNK | 0o777
                ) << 16
                archive.writestr(member, target)
            for name in directories:
                member = zipfile.ZipInfo(name.rstrip("/") + "/")
                member.create_system = 3
                member.external_attr = (
                    stat.S_IFDIR | 0o755
                ) << 16
                archive.writestr(member, b"")
            for name, content in (files or {}).items():
                archive.writestr(name, content)
        return output.getvalue()

    @staticmethod
    def duplicate_link_destination_tar_bytes() -> bytes:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            content = b"do not overwrite"
            regular = tarfile.TarInfo("sdk/output")
            regular.size = len(content)
            archive.addfile(regular, io.BytesIO(content))
            target_content = b"target"
            target = tarfile.TarInfo("sdk/target")
            target.size = len(target_content)
            archive.addfile(target, io.BytesIO(target_content))
            link = tarfile.TarInfo("sdk/output")
            link.type = tarfile.SYMTYPE
            link.linkname = "target"
            archive.addfile(link)
        return output.getvalue()

    def create_document(self, label: str) -> SBOMDocument:
        sbom_sha256 = hashlib.sha256(label.encode()).hexdigest()
        return SBOMDocument.objects.create(
            docker_image=None,
            manufacturer="Example Devices",
            product_name=label,
            product_version="1.0",
            original_filename=f"{label}.cdx.json",
            uploaded_file="",
            source_path="",
            file_sha256=sbom_sha256,
            format=SBOMDocument.Format.CYCLONEDX_JSON,
            spec_version="1.6",
            serial_number=f"urn:uuid:{label}",
            document_version=1,
            generator_name="EMBA",
            generator_version="2.0",
            source_type="upload",
            scope="document",
        )

    def create_source_artifact(
        self,
        *,
        label: str,
        filename: str,
        content: bytes,
    ) -> tuple[SBOMDocument, SourceArtifact]:
        document = self.create_document(label)
        source_sha256 = hashlib.sha256(content).hexdigest()
        artifact = SourceArtifact(
            sbom_document=document,
            original_filename=filename,
            file_sha256=source_sha256,
            size=len(content),
        )
        artifact.source_archive.save(
            filename,
            ContentFile(content),
            save=True,
        )
        return document, artifact

    @staticmethod
    def extraction_root(artifact: SourceArtifact) -> Path:
        archive_path = Path(artifact.source_archive.path)
        return archive_path.parent / artifact.file_sha256

    def run_command(
        self,
        document: SBOMDocument,
        *,
        force: bool = False,
    ) -> str:
        stdout = StringIO()
        call_command(
            "extract_source_artifact",
            sbom_id=document.pk,
            force=force,
            stdout=stdout,
        )
        return stdout.getvalue()

    def assert_no_partial_extraction(
        self,
        artifact: SourceArtifact,
    ) -> None:
        archive_path = Path(artifact.source_archive.path)
        self.assertFalse(self.extraction_root(artifact).exists())
        self.assertEqual(
            list(
                archive_path.parent.glob(
                    f".{artifact.file_sha256}.extract-*"
                )
            ),
            [],
        )

    def test_extracts_zip_archive(self) -> None:
        archive_bytes = self.zip_bytes(
            {
                "sdk/README.txt": b"source evidence\n",
                "sdk/package/Makefile": b"PKG_NAME:=example\n",
            }
        )
        document, artifact = self.create_source_artifact(
            label="normal-zip",
            filename="vendor-source.zip",
            content=archive_bytes,
        )

        output = self.run_command(document)

        extraction_root = self.extraction_root(artifact)
        extracted = extraction_root / "extracted"
        self.assertEqual(
            (extracted / "sdk/README.txt").read_bytes(),
            b"source evidence\n",
        )
        self.assertEqual(
            (extracted / "sdk/package/Makefile").read_bytes(),
            b"PKG_NAME:=example\n",
        )
        self.assertTrue(
            (extraction_root / EXTRACTION_MARKER_FILENAME).is_file()
        )
        self.assertIn("Verified SHA-256", output)
        self.assertIn("Extraction completed: 2 files", output)
        self.assertEqual(
            Path(artifact.source_archive.path).read_bytes(),
            archive_bytes,
        )

    def test_extracts_all_supported_tar_formats(self) -> None:
        formats = (
            ("normal-tar", "vendor-source.tar", "w"),
            ("normal-tar-gz", "vendor-source.tar.gz", "w:gz"),
            ("normal-tgz", "vendor-source.tgz", "w:gz"),
            ("normal-tar-xz", "vendor-source.tar.xz", "w:xz"),
        )
        for label, filename, mode in formats:
            with self.subTest(filename=filename):
                archive_bytes = self.tar_bytes(
                    {
                        "gpl/README": b"GPL source\n",
                        "gpl/package.mk": b"VERSION=1.2.3\n",
                    },
                    mode=mode,
                )
                document, artifact = self.create_source_artifact(
                    label=label,
                    filename=filename,
                    content=archive_bytes,
                )

                output = self.run_command(document)

                extracted = self.extraction_root(artifact) / "extracted"
                self.assertEqual(
                    (extracted / "gpl/README").read_bytes(),
                    b"GPL source\n",
                )
                self.assertEqual(
                    (extracted / "gpl/package.mk").read_bytes(),
                    b"VERSION=1.2.3\n",
                )
                self.assertIn("Extraction completed: 2 files", output)

    def test_reports_sbom_without_source_artifact(self) -> None:
        document = self.create_document("no-source-artifact")

        with self.assertRaisesMessage(
            CommandError,
            f"SBOMDocument {document.pk} has no SourceArtifact.",
        ):
            self.run_command(document)

    def test_rejects_missing_archive(self) -> None:
        document, artifact = self.create_source_artifact(
            label="missing-archive",
            filename="missing.zip",
            content=self.zip_bytes({"README": b"source"}),
        )
        artifact.source_archive.storage.delete(
            artifact.source_archive.name
        )

        with self.assertRaisesMessage(
            CommandError,
            "Stored source archive does not exist",
        ):
            self.run_command(document)

        self.assert_no_partial_extraction(artifact)

    def test_rejects_sha256_mismatch(self) -> None:
        document, artifact = self.create_source_artifact(
            label="sha-mismatch",
            filename="source.zip",
            content=self.zip_bytes({"README": b"original"}),
        )
        archive_path = Path(artifact.source_archive.path)
        archive_path.write_bytes(
            self.zip_bytes({"README": b"tampered"})
        )

        with self.assertRaisesMessage(
            CommandError,
            "Source archive SHA-256 mismatch",
        ):
            self.run_command(document)

        self.assert_no_partial_extraction(artifact)

    def test_rejects_escaping_paths_without_partial_files(self) -> None:
        attacks = (
            ("path-traversal", "../outside.txt", "path traversal"),
            ("absolute-path", "/outside.txt", "absolute path"),
            (
                "windows-absolute-path",
                "C:\\outside.txt",
                "absolute path",
            ),
        )
        for label, member_name, message in attacks:
            with self.subTest(member_name=member_name):
                document, artifact = self.create_source_artifact(
                    label=label,
                    filename="escaping-path.zip",
                    content=self.zip_bytes(
                        {
                            "safe/file.txt": b"partial",
                            member_name: b"escape",
                        }
                    ),
                )

                with self.assertRaisesMessage(CommandError, message):
                    self.run_command(document)

                self.assert_no_partial_extraction(artifact)
                self.assertEqual(
                    list(self.media_root.rglob("outside.txt")),
                    [],
                )

    def test_extracts_safe_internal_regular_file_symlinks(self) -> None:
        archives = (
            (
                "tar-internal-symlink",
                "links.tar.gz",
                self.tar_with_links(
                    files={"sdk/lib/libfoo.so.1": b"shared library"},
                    symlinks=(("sdk/lib/libfoo.so", "libfoo.so.1"),),
                ),
            ),
            (
                "zip-internal-symlink",
                "links.zip",
                self.zip_with_symlinks(
                    files={"sdk/lib/libfoo.so.1": b"shared library"},
                    symlinks=(("sdk/lib/libfoo.so", "libfoo.so.1"),),
                ),
            ),
        )
        for label, filename, archive_bytes in archives:
            with self.subTest(filename=filename):
                document, artifact = self.create_source_artifact(
                    label=label,
                    filename=filename,
                    content=archive_bytes,
                )

                self.run_command(document)

                link = (
                    self.extraction_root(artifact)
                    / "extracted/sdk/lib/libfoo.so"
                )
                self.assertTrue(link.is_symlink())
                self.assertEqual(link.readlink(), Path("libfoo.so.1"))
                self.assertEqual(link.read_bytes(), b"shared library")

    def test_extracts_safe_internal_directory_symlink(self) -> None:
        document, artifact = self.create_source_artifact(
            label="directory-symlink",
            filename="directory-link.tar.gz",
            content=self.tar_with_links(
                files={"sdk/releases/v1/README": b"release one"},
                directories=("sdk", "sdk/releases", "sdk/releases/v1"),
                symlinks=(("sdk/current", "releases/v1"),),
            ),
        )

        self.run_command(document)

        link = (
            self.extraction_root(artifact) / "extracted/sdk/current"
        )
        self.assertTrue(link.is_symlink())
        self.assertTrue(link.is_dir())
        self.assertEqual(link.readlink(), Path("releases/v1"))
        self.assertEqual(
            (link / "README").read_bytes(),
            b"release one",
        )

    def test_extracts_safe_internal_hardlink(self) -> None:
        document, artifact = self.create_source_artifact(
            label="internal-hardlink",
            filename="hardlink.tar.gz",
            content=self.tar_with_links(
                files={"sdk/original.txt": b"same inode"},
                hardlinks=(("sdk/copy.txt", "original.txt"),),
            ),
        )

        self.run_command(document)

        extracted = self.extraction_root(artifact) / "extracted/sdk"
        original = extracted / "original.txt"
        copy = extracted / "copy.txt"
        self.assertFalse(copy.is_symlink())
        self.assertEqual(copy.read_bytes(), b"same inode")
        self.assertTrue(original.samefile(copy))

    def test_extracts_safe_symlink_chain(self) -> None:
        document, artifact = self.create_source_artifact(
            label="internal-link-chain",
            filename="chain.tar.gz",
            content=self.tar_with_links(
                files={"sdk/lib/libfoo.so.1": b"chain target"},
                symlinks=(
                    ("sdk/lib/libfoo.so", "libfoo.so.0"),
                    ("sdk/lib/libfoo.so.0", "libfoo.so.1"),
                ),
            ),
        )

        self.run_command(document)

        link = (
            self.extraction_root(artifact)
            / "extracted/sdk/lib/libfoo.so"
        )
        self.assertTrue(link.is_symlink())
        self.assertEqual(link.readlink(), Path("libfoo.so.0"))
        self.assertEqual(link.read_bytes(), b"chain target")

    def test_extracts_versioned_shared_library_symlink_pattern(self) -> None:
        document, artifact = self.create_source_artifact(
            label="versioned-library-link",
            filename="versioned-library.tar.gz",
            content=self.tar_with_links(
                files={
                    "sdk/usr/lib/libfoo.so.1.2.3": b"versioned library"
                },
                symlinks=(
                    ("sdk/usr/lib/libfoo.so", "libfoo.so.1.2.3"),
                ),
            ),
        )

        self.run_command(document)

        link = (
            self.extraction_root(artifact)
            / "extracted/sdk/usr/lib/libfoo.so"
        )
        self.assertTrue(link.is_symlink())
        self.assertEqual(link.readlink(), Path("libfoo.so.1.2.3"))
        self.assertEqual(link.read_bytes(), b"versioned library")

    def test_rejects_links_that_escape_extraction_root(self) -> None:
        attacks = (
            (
                "tar-symlink",
                "links.tar.gz",
                self.tar_with_links(
                    symlinks=(("sdk/escape-link", "../../outside.txt"),)
                ),
            ),
            (
                "tar-hardlink",
                "links.tar.gz",
                self.tar_with_links(
                    hardlinks=(("sdk/escape-link", "../../outside.txt"),)
                ),
            ),
            (
                "zip-symlink",
                "links.zip",
                self.zip_with_symlinks(
                    symlinks=(("sdk/escape-link", "../../outside.txt"),)
                ),
            ),
        )
        for label, filename, archive_bytes in attacks:
            with self.subTest(label=label):
                document, artifact = self.create_source_artifact(
                    label=label,
                    filename=filename,
                    content=archive_bytes,
                )

                with self.assertRaisesMessage(
                    CommandError,
                    "escapes extraction root",
                ):
                    self.run_command(document)

                self.assert_no_partial_extraction(artifact)
                self.assertEqual(
                    list(self.media_root.rglob("outside.txt")),
                    [],
                )

    def test_rejects_absolute_link_targets(self) -> None:
        attacks = (
            ("posix", "/etc/passwd"),
            ("windows", "C:\\Windows\\system.ini"),
        )
        for label, target in attacks:
            with self.subTest(target=target):
                document, artifact = self.create_source_artifact(
                    label=f"absolute-link-{label}",
                    filename="absolute-link.tar.gz",
                    content=self.tar_with_links(
                        symlinks=(("sdk/link", target),)
                    ),
                )

                with self.assertRaisesMessage(
                    CommandError,
                    "uses an absolute target",
                ):
                    self.run_command(document)

                self.assert_no_partial_extraction(artifact)

    def test_rejects_symlink_chain_that_escapes_root(self) -> None:
        document, artifact = self.create_source_artifact(
            label="escaping-link-chain",
            filename="escaping-chain.tar.gz",
            content=self.tar_with_links(
                symlinks=(
                    ("sdk/link-a", "link-b"),
                    ("sdk/link-b", "../../outside"),
                )
            ),
        )

        with self.assertRaisesMessage(
            CommandError,
            "escapes extraction root",
        ):
            self.run_command(document)

        self.assert_no_partial_extraction(artifact)

    def test_rejects_symlink_cycle(self) -> None:
        document, artifact = self.create_source_artifact(
            label="link-cycle",
            filename="cycle.tar.gz",
            content=self.tar_with_links(
                symlinks=(
                    ("sdk/link-a", "link-b"),
                    ("sdk/link-b", "link-a"),
                )
            ),
        )

        with self.assertRaisesMessage(CommandError, "link cycle detected"):
            self.run_command(document)

        self.assert_no_partial_extraction(artifact)

    def test_rejects_missing_link_target(self) -> None:
        document, artifact = self.create_source_artifact(
            label="missing-link-target",
            filename="missing-target.tar.gz",
            content=self.tar_with_links(
                symlinks=(("sdk/link", "missing-file"),)
            ),
        )

        with self.assertRaisesMessage(
            CommandError,
            "link target does not exist",
        ):
            self.run_command(document)

        self.assert_no_partial_extraction(artifact)

    def test_rejects_link_overwrite_attempt(self) -> None:
        document, artifact = self.create_source_artifact(
            label="link-overwrite",
            filename="overwrite.tar.gz",
            content=self.duplicate_link_destination_tar_bytes(),
        )

        with self.assertRaisesMessage(
            CommandError,
            "duplicate destination",
        ):
            self.run_command(document)

        self.assert_no_partial_extraction(artifact)

    def test_second_run_detects_completed_extraction(self) -> None:
        document, artifact = self.create_source_artifact(
            label="safe-rerun",
            filename="source.tgz",
            content=self.tar_bytes({"sdk/README": b"source"}),
        )
        self.run_command(document)
        extracted_file = (
            self.extraction_root(artifact) / "extracted/sdk/README"
        )
        original_stat = extracted_file.stat()

        output = self.run_command(document)

        self.assertIn("Already extracted; no files were changed.", output)
        self.assertEqual(extracted_file.read_bytes(), b"source")
        self.assertEqual(extracted_file.stat().st_ino, original_stat.st_ino)
        self.assertEqual(
            extracted_file.stat().st_mtime_ns,
            original_stat.st_mtime_ns,
        )

    def test_force_replaces_only_existing_extraction(self) -> None:
        first_archive = self.zip_bytes(
            {"sdk/README": b"first source"}
        )
        second_archive = self.zip_bytes(
            {"sdk/README": b"second source"}
        )
        first_document, first_artifact = self.create_source_artifact(
            label="force-first",
            filename="first.zip",
            content=first_archive,
        )
        second_document, second_artifact = self.create_source_artifact(
            label="force-second",
            filename="second.zip",
            content=second_archive,
        )
        self.run_command(first_document)
        self.run_command(second_document)
        first_file = (
            self.extraction_root(first_artifact)
            / "extracted/sdk/README"
        )
        second_root = self.extraction_root(second_artifact)
        second_file = second_root / "extracted/sdk/README"
        second_marker = second_root / EXTRACTION_MARKER_FILENAME
        second_marker_bytes = second_marker.read_bytes()
        second_archive_path = Path(second_artifact.source_archive.path)
        second_archive_bytes = second_archive_path.read_bytes()
        first_file.write_bytes(b"locally modified")

        output = self.run_command(first_document, force=True)

        self.assertIn("Extraction completed: 1 files", output)
        self.assertEqual(first_file.read_bytes(), b"first source")
        self.assertEqual(
            Path(first_artifact.source_archive.path).read_bytes(),
            first_archive,
        )
        self.assertEqual(second_file.read_bytes(), b"second source")
        self.assertEqual(second_marker.read_bytes(), second_marker_bytes)
        self.assertEqual(second_archive_path.read_bytes(), second_archive_bytes)
