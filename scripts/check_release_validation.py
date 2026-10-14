#!/usr/bin/env python3
"""Offline acceptance and adversarial checks for the publication gate."""
from __future__ import annotations

import base64
import copy
import csv
import hashlib
import io
import tarfile
import unittest
import zipfile

from verify_release import (EXPECTED_JOBS, REPOSITORY, checksums, filenames, release_version,
                            validate_ci, validate_distributions, validate_release)

VERSION = "0.2.0a1"
PROJECT = {"name": "mcp-trust-monitor", "version": VERSION, "requires-python": ">=3.10",
           "readme": "README.md",
           "dependencies": ["mcp>=1.30,<1.31"],
           "scripts": {"mcp-trust-monitor": "mcp_trust_monitor.library_cli:main"}}
SOURCE = {"mcp_trust_monitor/__init__.py": b'__version__ = "0.2.0a1"\n',
          "mcp_trust_monitor/library_cli.py": b"def main(): pass\n",
          "mcp_trust_monitor/py.typed": b"", "pyproject.toml": b"fixture\n",
          "examples/installed_consumer.py": b"# Synthetic installed consumer\n",
          "README.md": b"Synthetic fixture\n", "LICENSE": b"MIT\n"}
METADATA = b"Metadata-Version: 2.4\nName: mcp-trust-monitor\nVersion: 0.2.0a1\nRequires-Python: >=3.10\nRequires-Dist: mcp<1.31,>=1.30\n\nSynthetic fixture\n"


def distributions(wheel_overrides=None, sdist_overrides=None, metadata=METADATA, omit_sdist=()):
    prefix = f"mcp_trust_monitor-{VERSION}.dist-info/"
    files = {name: data for name, data in SOURCE.items() if name.startswith("mcp_trust_monitor/")}
    files.update({prefix + "METADATA": metadata,
                  prefix + "WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
                  prefix + "entry_points.txt": b"[console_scripts]\nmcp-trust-monitor = mcp_trust_monitor.library_cli:main\n",
                  prefix + "licenses/LICENSE": SOURCE["LICENSE"]})
    files.update(wheel_overrides or {})
    rows = []
    for name, content in files.items():
        encoded = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        rows.append((name, "sha256=" + encoded, str(len(content))))
    rows.append((prefix + "RECORD", "", ""))
    record = io.StringIO()
    csv.writer(record, lineterminator="\n").writerows(rows)
    files[prefix + "RECORD"] = record.getvalue().encode()
    wheel = io.BytesIO()
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    files = dict(SOURCE, **{"PKG-INFO": metadata})
    files.update(sdist_overrides or {})
    for name in omit_sdist:
        del files[name]
    sdist = io.BytesIO()
    with tarfile.open(fileobj=sdist, mode="w:gz") as archive:
        for name, content in files.items():
            member = tarfile.TarInfo(f"mcp_trust_monitor-{VERSION}/" + name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    names = filenames(VERSION)
    return {names[0]: wheel.getvalue(), names[1]: sdist.getvalue()}


class PublicationGateTests(unittest.TestCase):
    def setUp(self):
        self.commit = "1" * 40
        self.run = {"head_sha": self.commit, "head_branch": "main", "event": "push",
                    "status": "completed", "conclusion": "success", "workflow_id": 42,
                    "repository": {"full_name": REPOSITORY}}
        self.jobs = [{"name": name, "status": "completed", "conclusion": "success"} for name in EXPECTED_JOBS]

    def test_accepts_complete_exact_commit_ci(self):
        validate_ci(self.run, self.jobs, self.commit, 42)

    def test_rejects_other_commit_branch_event_workflow_or_repository(self):
        for key, value in (("head_sha", "2" * 40), ("head_branch", "feature"), ("event", "pull_request"),
                           ("workflow_id", 43), ("conclusion", "failure"), ("status", "in_progress"),
                           ("repository", {"full_name": "other/repository"})):
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_ci(dict(self.run, **{key: value}), self.jobs, self.commit, 42)

    def test_rejects_missing_skipped_failed_or_duplicate_matrix_jobs(self):
        altered = copy.deepcopy(self.jobs)
        altered[0]["conclusion"] = "skipped"
        failed = copy.deepcopy(self.jobs)
        failed[0]["conclusion"] = "failure"
        for jobs in (self.jobs[:-1], altered, failed, self.jobs + self.jobs[:1]):
            with self.subTest(jobs=jobs), self.assertRaises(ValueError):
                validate_ci(self.run, jobs, self.commit, 42)

    def test_requires_published_immutable_matching_release(self):
        release = {"tag_name": "v" + VERSION, "immutable": True, "draft": False, "published_at": "2026-10-14"}
        validate_release(release, "v" + VERSION)
        for change in ({"immutable": False}, {"draft": True}, {"published_at": None}, {"tag_name": "v9.9.9"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_release(dict(release, **change), "v" + VERSION)

    def test_tag_validation_excludes_shell_paths_and_nonversions(self):
        self.assertEqual(release_version("v" + VERSION), VERSION)
        for tag in ("", "main", "v1.2.3/../main", "v1.2.3; echo bad", "v1.2.3\n", "v1.2.3$(id)"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release_version(tag)

    def test_checksums_require_exact_dist_inventory_and_unique_safe_names(self):
        names = filenames(VERSION)
        manifest = "".join("1" * 64 + "  " + name + "\n" for name in names).encode()
        self.assertEqual(set(checksums(manifest, names)), set(names))
        for data in (b"", manifest + manifest, manifest.replace(names[0].encode(), b"../evil.whl"),
                     manifest + b"0" * 64 + b"  extra.whl\n", manifest.replace(b"1", b"x", 1)):
            with self.subTest(data=data), self.assertRaises(ValueError):
                checksums(data, names)

    def test_accepts_matching_distributions_and_source(self):
        self.assertEqual(validate_distributions(distributions(), SOURCE, PROJECT, VERSION)["wheel_package_files"], 3)

    def test_rejects_changed_or_extra_wheel_code_even_with_valid_record(self):
        for change in ({"mcp_trust_monitor/library_cli.py": b"changed\n"}, {"unexpected.py": b"injected\n"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_distributions(distributions(wheel_overrides=change), SOURCE, PROJECT, VERSION)

    def test_rejects_changed_sdist_source_or_paths(self):
        for change in ({"README.md": b"unreviewed\n"}, {"../outside": b"bad\n"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_distributions(distributions(sdist_overrides=change), SOURCE, PROJECT, VERSION)

    def test_rejects_omitted_tracked_nonpackage_source(self):
        with self.assertRaises(ValueError):
            validate_distributions(distributions(omit_sdist=["examples/installed_consumer.py"]),
                                   SOURCE, PROJECT, VERSION)

    def test_rejects_unreviewed_dependency_metadata_and_entry_points(self):
        bad_metadata = METADATA.replace(b"Requires-Dist: mcp<1.31,>=1.30", b"Requires-Dist: unreviewed-dependency")
        with self.assertRaises(ValueError):
            validate_distributions(distributions(metadata=bad_metadata), SOURCE, PROJECT, VERSION)
        name = f"mcp_trust_monitor-{VERSION}.dist-info/entry_points.txt"
        with self.assertRaises(ValueError):
            validate_distributions(distributions(wheel_overrides={name: b"[console_scripts]\nbad=bad:main\n"}), SOURCE, PROJECT, VERSION)

    def test_rejects_tag_source_version_mismatch(self):
        with self.assertRaises(ValueError):
            validate_distributions(distributions(), SOURCE, dict(PROJECT, version="9.9.9"), VERSION)

    def test_rejects_wrong_wheel_tags_and_readme(self):
        name = f"mcp_trust_monitor-{VERSION}.dist-info/WHEEL"
        for content in (b"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: py3-none-any\n",
                        b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: cp312-cp312-linux_x86_64\n"):
            with self.subTest(content=content), self.assertRaises(ValueError):
                validate_distributions(distributions(wheel_overrides={name: content}), SOURCE, PROJECT, VERSION)
        with self.assertRaises(ValueError):
            validate_distributions(distributions(metadata=METADATA.replace(b"Synthetic fixture", b"Other content")),
                                   SOURCE, PROJECT, VERSION)


if __name__ == "__main__":
    unittest.main(verbosity=2)
