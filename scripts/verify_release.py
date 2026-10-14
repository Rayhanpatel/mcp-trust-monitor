#!/usr/bin/env python3
"""Validate reviewed immutable GitHub release assets before the isolated PyPI job.

Requires Python 3.11+ and packaging==26.3 for the command-line entry point.
No release code is executed and no archive is extracted (REQ-LIB-02).
"""
from __future__ import annotations

import argparse
import base64
import configparser
import csv
import email.parser
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import urllib.parse
import urllib.request
import zipfile

from packaging.markers import Marker
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet

REPOSITORY = "Rayhanpatel/mcp-trust-monitor"
EXPECTED_JOBS = {f"test / {os_name} / Python {python}"
                 for os_name in ("ubuntu-24.04", "macos-15")
                 for python in ("3.10.22", "3.12.15")}
MAX_ASSET_BYTES = 20 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def release_version(tag):
    require(isinstance(tag, str) and re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:(?:a|b|rc)[0-9]+)?", tag),
            "tag must be a release version such as v0.2.0a1")
    return tag[1:]


def filenames(version):
    return (f"mcp_trust_monitor-{version}-py3-none-any.whl", f"mcp_trust_monitor-{version}.tar.gz")


def checksums(data, expected_names):
    result = {}
    for line in data.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        require(match is not None, "invalid SHA256SUMS line")
        digest, name = match.groups()
        require(name not in result, "duplicate checksum filename")
        result[name] = digest
    require(set(result) == set(expected_names), "SHA256SUMS must name exactly the wheel and sdist")
    return result


def validate_release(release, tag):
    require(release.get("tag_name") == tag, "release tag mismatch")
    require(release.get("immutable") is True and release.get("draft") is False
            and bool(release.get("published_at")), "release must be published and immutable")


def validate_ci(run, jobs, commit, workflow_id):
    require(run.get("head_sha") == commit and run.get("head_branch") == "main"
            and run.get("event") == "push" and run.get("status") == "completed"
            and run.get("conclusion") == "success" and run.get("workflow_id") == workflow_id
            and run.get("repository", {}).get("full_name") == REPOSITORY,
            "CI must be a successful main push for the exact tagged commit")
    names = [job.get("name") for job in jobs]
    require(len(names) == len(set(names)), "duplicate CI job names")
    by_name = {job["name"]: job for job in jobs}
    require(EXPECTED_JOBS <= set(by_name), "CI did not run the complete supported matrix")
    require(all(by_name[name].get("status") == "completed"
                and by_name[name].get("conclusion") == "success" for name in EXPECTED_JOBS),
            "every required matrix job must succeed")


def validate_metadata(data, project, version):
    metadata = email.parser.BytesParser().parsebytes(data)
    for name, expected in (("Name", "mcp-trust-monitor"), ("Version", version)):
        require(metadata.get_all(name) == [expected], f"distribution {name} mismatch")
    require(SpecifierSet(metadata["Requires-Python"]) == SpecifierSet(project["requires-python"]),
            "Requires-Python differs from source")
    expected = {Requirement(value) for value in project["dependencies"]}
    extras = project.get("optional-dependencies", {})
    for extra, dependencies in extras.items():
        for value in dependencies:
            requirement = Requirement(value)
            marker = f"extra == '{extra}'"
            if requirement.marker:
                marker = f"({requirement.marker}) and {marker}"
            requirement.marker = Marker(marker)
            expected.add(requirement)
    require(set(metadata.get_all("Provides-Extra", [])) == set(extras), "distribution extras differ from source")
    require({Requirement(value) for value in metadata.get_all("Requires-Dist", [])} == expected,
            "distribution dependencies differ from source")


def validate_distributions(assets, source, project, version):
    """Bind package bytes, metadata, and sdist source to the tested Git commit."""
    require(project["name"] == "mcp-trust-monitor" and project["version"] == version,
            "tag version differs from tagged pyproject.toml")
    wheel_name, sdist_name = filenames(version)
    package = {name: data for name, data in source.items() if name.startswith("mcp_trust_monitor/")}
    require(bool(package), "tagged source has no package")
    prefix = f"mcp_trust_monitor-{version}.dist-info/"
    metadata_files = {prefix + name for name in ("METADATA", "WHEEL", "RECORD", "entry_points.txt", "licenses/LICENSE")}
    with zipfile.ZipFile(io.BytesIO(assets[wheel_name])) as wheel:
        names = wheel.namelist()
        require(len(names) == len(set(names)), "wheel has duplicate members")
        require(set(names) == set(package) | metadata_files, "unexpected or missing wheel members")
        for name, expected in package.items():
            require(wheel.read(name) == expected, f"wheel source mismatch: {name}")
        wheel_metadata = wheel.read(prefix + "METADATA")
        validate_metadata(wheel_metadata, project, version)
        wheel_headers = email.parser.BytesParser().parsebytes(wheel.read(prefix + "WHEEL"))
        for name, expected in (("Wheel-Version", "1.0"), ("Root-Is-Purelib", "true"), ("Tag", "py3-none-any")):
            require(wheel_headers.get_all(name) == [expected], f"unexpected wheel {name}")
        readme = project["readme"]
        readme_path = readme if isinstance(readme, str) else readme["file"]
        require(email.parser.BytesParser().parsebytes(wheel_metadata).get_payload(decode=True) == source[readme_path],
                "distribution README differs from source")
        require(wheel.read(prefix + "licenses/LICENSE") == source["LICENSE"], "wheel license mismatch")
        entries = configparser.ConfigParser()
        entries.read_string(wheel.read(prefix + "entry_points.txt").decode())
        require(entries.sections() == ["console_scripts"] and dict(entries["console_scripts"]) == project["scripts"],
                "wheel entry points differ from source")
        rows = list(csv.reader(io.StringIO(wheel.read(prefix + "RECORD").decode())))
        require(len(rows) == len(names) and {row[0] for row in rows} == set(names), "invalid wheel RECORD inventory")
        for name, digest, size in rows:
            if name == prefix + "RECORD":
                require(not digest and not size, "invalid RECORD self-entry")
            else:
                content = wheel.read(name)
                encoded = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
                require(digest == "sha256=" + encoded and size == str(len(content)), "wheel RECORD mismatch")
    archive_prefix = f"mcp_trust_monitor-{version}/"
    sdist_files = {}
    with tarfile.open(fileobj=io.BytesIO(assets[sdist_name]), mode="r:gz") as sdist:
        for member in sdist.getmembers():
            require(member.isfile() and member.name.startswith(archive_prefix), "unexpected sdist member")
            name = member.name[len(archive_prefix):]
            require(name not in sdist_files, "sdist has duplicate members")
            require(member.size <= MAX_ASSET_BYTES, "sdist member is too large")
            content = sdist.extractfile(member).read()
            sdist_files[name] = content
            if name != "PKG-INFO":
                require(name in source and content == source[name], f"sdist source mismatch: {name}")
    require(set(sdist_files) == set(source) | {"PKG-INFO"},
            "sdist must contain every tracked source file and only generated PKG-INFO")
    require(sdist_files["PKG-INFO"] == wheel_metadata, "wheel and sdist metadata differ")
    return {"wheel_package_files": len(package), "sdist_source_files": len(sdist_files) - 1}


def api(path):
    request = urllib.request.Request("https://api.github.com/repos/" + REPOSITORY + "/" + path,
        headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                 "Authorization": "Bearer " + os.environ["GH_TOKEN"], "User-Agent": "mtm-release-validation"})
    with urllib.request.urlopen(request, timeout=30) as response:
        body = response.read(10 * 1024 * 1024 + 1)
    require(len(body) <= 10 * 1024 * 1024, "GitHub API response too large")
    return json.loads(body)


def all_pages(path, key):
    rows = []
    separator = "&" if "?" in path else "?"
    for page in range(1, 11):
        batch = api(f"{path}{separator}per_page=100&page={page}")[key]
        rows.extend(batch)
        if len(batch) < 100:
            return rows
    raise ValueError("too many GitHub records to validate safely")


def source_at(commit):
    data = subprocess.check_output(["git", "archive", "--format=tar", commit])
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        members = archive.getmembers()
        require(all(member.isfile() or member.isdir() for member in members), "tagged source contains links")
        return {member.name: archive.extractfile(member).read() for member in members if member.isfile()}


def verify(tag, output, report):
    import tomllib
    require(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
            and os.environ.get("GITHUB_REF") == "refs/heads/main", "publication validation must run from main")
    version = release_version(tag)
    release = api("releases/tags/" + urllib.parse.quote(tag, safe=""))
    validate_release(release, tag)
    commit = subprocess.check_output(["git", "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}"], text=True).strip()
    require(re.fullmatch(r"[0-9a-f]{40}", commit), "invalid tag commit")
    subprocess.run(["git", "merge-base", "--is-ancestor", commit, "refs/remotes/origin/main"], check=True)
    remote = api("git/ref/tags/" + tag)["object"]
    for _ in range(5):
        if remote["type"] == "commit":
            break
        require(remote["type"] == "tag", "unsupported tag target")
        remote = api("git/tags/" + remote["sha"])["object"]
    require(remote["type"] == "commit" and remote["sha"] == commit, "local and remote tag targets differ")
    workflow_id = api("actions/workflows/ci.yml")["id"]
    candidates = all_pages(f"actions/workflows/{workflow_id}/runs?head_sha={commit}&branch=main&event=push&status=success", "workflow_runs")
    selected = None
    for run in candidates:
        jobs = all_pages(f"actions/runs/{run['id']}/jobs?filter=latest", "jobs")
        try:
            validate_ci(run, jobs, commit, workflow_id)
        except ValueError:
            continue
        selected = run
        break
    require(selected is not None, "no successful complete CI matrix for the exact main commit")
    required = {*filenames(version), "SHA256SUMS"}
    assets = [asset for asset in release["assets"] if asset["name"] in required]
    require(len(assets) == len(required) and {asset["name"] for asset in assets} == required,
            "release must have exactly one wheel, sdist and SHA256SUMS with expected names")
    downloaded = {}
    for asset in assets:
        name = asset["name"]
        require(asset.get("state") == "uploaded" and 0 < asset["size"] <= MAX_ASSET_BYTES, "invalid release asset")
        expected_url = f"https://github.com/{REPOSITORY}/releases/download/{tag}/{name}"
        require(asset["browser_download_url"] == expected_url, "unexpected release asset URL")
        # Public release asset download: never forward the API token to redirects.
        with urllib.request.urlopen(expected_url, timeout=60) as response:
            content = response.read(MAX_ASSET_BYTES + 1)
        require(len(content) == asset["size"], "release asset size mismatch")
        digest = hashlib.sha256(content).hexdigest()
        require(asset.get("digest") == "sha256:" + digest, "GitHub release asset digest mismatch")
        downloaded[name] = content
    sums = checksums(downloaded.pop("SHA256SUMS"), filenames(version))
    require(all(hashlib.sha256(downloaded[name]).hexdigest() == digest for name, digest in sums.items()),
            "release SHA256SUMS mismatch")
    source = source_at(commit)
    project = tomllib.loads(source["pyproject.toml"].decode())["project"]
    inventory = validate_distributions(downloaded, source, project, version)
    # Recheck immutable release identity after downloads; publication never rebuilds.
    latest = api(f"releases/{release['id']}")
    validate_release(latest, tag)
    def asset_identity(item):
        return (item["id"], item["name"], item["size"], item.get("digest"), item["browser_download_url"])
    require(sorted(map(asset_identity, latest["assets"])) == sorted(map(asset_identity, release["assets"])),
            "release assets changed during validation")
    require(not output.exists(), "verified output directory already exists")
    output.mkdir(parents=True)
    for name, content in downloaded.items():
        (output / name).write_bytes(content)
    result = {"validated": True, "repository": REPOSITORY, "tag": tag, "commit": commit,
              "release_id": release["id"], "immutable": True, "ci_run_id": selected["id"],
              "sha256": sums, **inventory}
    report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    try:
        verify(os.environ.get("RELEASE_TAG", ""), args.output, args.report)
    except Exception as exc:
        args.report.write_text(json.dumps({"validated": False, "error": type(exc).__name__, "detail": str(exc)}, indent=2) + "\n")
        raise


if __name__ == "__main__":
    main()
