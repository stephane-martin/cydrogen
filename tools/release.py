import argparse
import io
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import date
from enum import StrEnum
from pathlib import Path
from typing import Any, Self

import tomlkit
from semver import Version

THIS_DIR = Path(__file__).parent
ROOT = THIS_DIR.parent.resolve()
CHANGELOG_JSON_FNAME = ROOT / "CHANGELOG.json"
CHANGELOG_TPL_FNAME = ROOT / "CHANGELOG.tpl.md"
CHANGELOG_MD_FNAME = ROOT / "CHANGELOG.md"
PYPROJECT_TOML_FNAME = ROOT / "pyproject.toml"
LAST_RELEASE_CHANGES_FNAME = ROOT / "last_release_changes.md"

ISSUE_URL_TPL = "https://github.com/stephane-martin/cydrogen/issues/"

with open(CHANGELOG_TPL_FNAME, "r", encoding="utf-8") as f:
    CHANGELOG_TEMPLATE = f.read().strip()


class ChangeType(StrEnum):
    """
    Added:      new features.
    Changed:    changes in existing functionality.
    Deprecated: soon-to-be removed features.
    Removed:    now removed features.
    Fixed:      any bug fixes.
    Security:   in case of vulnerabilities.
    """

    SECURITY = "security"
    ADDED = "added"
    CHANGED = "changed"
    FIXED = "fixed"
    REMOVED = "removed"
    DEPRECATED = "deprecated"


# CHANGELOG.json example:
# {
# 	"unreleased": {
# 		"added": [
# 			"Expose `pad` and `unpad` functions."
# 		],
#       "fixed": [
#           "blah"
#       ]
# 	},
# 	"v0.0.4": {
# 		"date": "2025-06-04",
# 		"added": [
# 			"Initial release published on [PyPI](https://pypi.org/project/cydrogen/)."
# 		]
# 	}
# }


class PyProject:
    data: dict[str, Any]

    def __init__(self):
        self.data = {}

    @property
    def version(self) -> Version:
        """Get the version from the pyproject.toml."""
        v: str = self.data["project"]["version"]
        v = v.lstrip(" v").rstrip()
        return Version.parse(v)

    @version.setter
    def version(self, v: Version | str) -> None:
        """Set the version in the pyproject.toml."""
        if isinstance(v, str):
            v = Version.parse(v.lstrip(" v").rstrip())
        self.data["project"]["version"] = str(v)

    @classmethod
    def load(cls) -> Self:
        with PYPROJECT_TOML_FNAME.open("r", encoding="utf-8") as f:
            data = tomlkit.load(f)
        instance = cls()
        instance.data = data
        return instance

    def save(self) -> None:
        with PYPROJECT_TOML_FNAME.open("w", encoding="utf-8") as f:
            tomlkit.dump(self.data, f)


@dataclass
class Release:
    date: date
    version: Version
    changes: dict[ChangeType, list[str]]


@dataclass
class Changelog:
    unreleased_changes: dict[ChangeType, list[str]]
    releases: list[Release]

    @classmethod
    def load(cls) -> Self:
        with CHANGELOG_JSON_FNAME.open("r", encoding="utf-8") as f:
            data = json.load(f)

        changes: list[str] = []

        unreleased_changes: dict[ChangeType, list[str]] = {}

        unreleased = data.get("unreleased", {})
        if unreleased:
            for ctype in unreleased:
                changes = []
                for change in unreleased[ctype]:
                    change = change.lstrip(" -").rstrip(" .")
                    if change:
                        change += "."
                        changes.append(change)
                if changes:
                    unreleased_changes[ChangeType(ctype.lower())] = changes

        releases: list[Release] = []
        v: str
        for v, release_data in data.items():
            if v == "unreleased":
                continue
            release_date = date.fromisoformat(release_data["date"])
            version = Version.parse(v.lstrip(" v").strip())
            release_changes: dict[ChangeType, list[str]] = {}
            for ctype in release_data:
                if ctype == "date":
                    continue
                change_type = ChangeType(ctype.lower())
                changes = []
                for change in release_data[ctype]:
                    change = change.strip()
                    if change:
                        change = change + "." if not change.endswith(".") else change
                        changes.append(change)
                if changes:
                    release_changes[change_type] = changes

            if release_changes:
                release = Release(date=release_date, version=version, changes=release_changes)
                releases.append(release)

        releases.sort(key=lambda r: r.date, reverse=True)

        return cls(
            unreleased_changes=unreleased_changes,
            releases=releases,
        )

    def to_json(self) -> str:
        data: dict[str, Any] = dict()
        if self.unreleased_changes:
            data["unreleased"] = {str(k): v for k, v in self.unreleased_changes.items() if v}
        if self.releases:
            for release in self.releases:
                changes: dict[str, list[str]] = {k.value: v for k, v in release.changes.items()}
                changes_and_date: dict[str, Any] = {
                    "date": release.date.isoformat(),
                    **changes,
                }
                data[f"v{release.version}"] = changes_and_date

        return json.dumps(data, indent=4, ensure_ascii=False)

    def to_markdown(self) -> str:
        md = io.StringIO()
        md.write(CHANGELOG_TEMPLATE)
        md.write("\n\n")

        if self.unreleased_changes:
            md.write("## Unreleased\n\n")
            for change_type, changes in self.unreleased_changes.items():
                md.write(f"### {change_type.value.capitalize()}\n\n")
                for change in changes:
                    md.write(f"- {change}\n")
                md.write("\n")

        for release in self.releases:
            md.write(f"## v{release.version} - {release.date.isoformat()}\n\n")
            for ctype in ChangeType:
                changes = release.changes.get(ctype, [])
                if changes:
                    md.write(f"### {ctype.value.capitalize()}\n\n")
                    for change in changes:
                        md.write(f"- {change}\n")
                    md.write("\n")

        return md.getvalue()

    def save(self) -> None:
        self.releases.sort(key=lambda r: r.date, reverse=True)

        with CHANGELOG_JSON_FNAME.open("w", encoding="utf-8") as f:
            f.write(self.to_json())
        with CHANGELOG_MD_FNAME.open("w", encoding="utf-8") as f:
            f.write(self.to_markdown())

    def save_last_release_changes(self) -> None:
        """
        Save the last release changes to a file.
        """
        if not self.releases:
            print("No releases found in the changelog.")
            return
        last_release = self.releases[0]
        with LAST_RELEASE_CHANGES_FNAME.open("w", encoding="utf-8") as f:
            f.write("# Changes\n\n")
            for ctype, changes in last_release.changes.items():
                f.write(f"## {ctype.value.capitalize()}\n\n")
                for change in changes:
                    f.write(f"- {change}\n")
                f.write("\n")


def sync_changelog():
    """
    Sync the CHANGELOG.md with the CHANGELOG.json file.
    """
    Changelog.load().save()
    print("=> CHANGELOG.md generated")


def bump(v: str):
    """
    Bump the version in pyproject.toml and add a new release to the changelog.
    """
    v = v.lstrip(" v").rstrip()
    version = Version.parse(v)
    changelog: Changelog = Changelog.load()
    if any(release.version == version for release in changelog.releases):
        print(f"Version {version} already exists in the changelog.")
        sys.exit(1)
        return
    if not changelog.unreleased_changes:
        print("No unreleased changes found in the changelog.")
        sys.exit(1)
        return

    pyproject: PyProject = PyProject.load()
    if pyproject.version >= version:
        print(f"New version {version} must be greater than the current version {pyproject.version}.")
        sys.exit(1)
        return
    pyproject.version = version

    release = Release(
        date=date.today(),
        version=version,
        changes=changelog.unreleased_changes,
    )
    changelog.unreleased_changes = {}
    changelog.releases.append(release)

    pyproject.save()
    changelog.save()
    changelog.save_last_release_changes()
    print(f"=> Version {version} bumped and added to the changelog.")


def change(change_type: ChangeType, change: str):
    """
    Add a new change to the changelog in the unreleased section.
    """
    change = change.lstrip(" -").rstrip(" .")
    if not change:
        print("Change description cannot be empty.")
        sys.exit(1)
    change += "."
    # replace #SOME_NUMBER with the link to the issue
    change = re.sub(r"#(\d+)", rf"[#\1]({ISSUE_URL_TPL}\1)", change)

    changelog: Changelog = Changelog.load()
    changes = changelog.unreleased_changes.get(change_type, [])
    if change in changes:
        print(f"Change already exists in the changelog under {change_type.value}.")
        sys.exit(1)
    changes.append(change)
    changelog.unreleased_changes[change_type] = changes
    changelog.save()


def release() -> None:
    changelog: Changelog = Changelog.load()
    if changelog.unreleased_changes:
        print("There are still unreleased changes in the changelog. Please run 'bump' first.")
        sys.exit(1)
    if not changelog.releases:
        print("No release found in the changelog.")
        sys.exit(1)
    last_release = changelog.releases[0]
    pyproject: PyProject = PyProject.load()
    if pyproject.version != last_release.version:
        print(f"Version in pyproject.toml ({pyproject.version}) does not match the last release ({last_release.version}).")
        sys.exit(1)
    git_tag = f"v{last_release.version}"
    # check if the tag already exists
    try:
        subprocess.run(["git", "rev-parse", git_tag], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"Git tag {git_tag} already exists.")
        sys.exit(1)
    except subprocess.CalledProcessError:
        pass
    # check if there are any untracked file with `git ls-files -o --exclude-standard`
    untracked_files = (
        subprocess.run(["git", "ls-files", "-o", "--exclude-standard"], check=True, capture_output=True, text=True)
        .stdout.strip()
        .splitlines()
    )
    if untracked_files:
        print("There are untracked files in the repository.")
        for f in untracked_files:
            print(f"- {f}")
        # ask user to confirm
        confirm = input("Do you want to continue? (y/N): ").strip().lower()
        if confirm != "y":
            print("Aborting release.")
            sys.exit(1)
    # list all modified files with `git diff --name-only`
    modified = subprocess.run(["git", "diff", "--name-only"], check=True, capture_output=True, text=True).stdout.strip().splitlines()
    if modified:
        print("There are modified files in the repository\n")
        subprocess.run(["git", "--no-pager", "diff", "--minimal"], check=True)
        # ask user to confirm
        confirm = input("Do you want to continue? (y/N): ").strip().lower()
        if confirm != "y":
            print("Aborting release.")
            sys.exit(1)
    if modified or untracked_files:
        subprocess.run(["git", "add", "--verbose", "."], check=True)
        subprocess.run(["git", "commit", "-m", f"chore: bump version to {last_release.version}"], check=True)
    # apply the tag
    subprocess.run(["git", "tag", "-a", git_tag, "-m", f"Release {last_release.version}"], check=True)
    # push the changes
    subprocess.run(["git", "push"], check=True)
    subprocess.run(["git", "push", "--tags"], check=True)


def get_parser():
    parser = argparse.ArgumentParser(description="tools to manage the changelog.")
    subs = parser.add_subparsers(dest="command", title="commands", description="available commands")
    _ = subs.add_parser("sync", help="Generate CHANGELOG.md from CHANGELOG.json")
    bump = subs.add_parser("bump", help="Bump version in pyproject.toml and add a new release to the changelog")
    bump.add_argument("version", type=str, help="Target new version (eg. 1.0.0, 2.1.3, etc.)")
    change = subs.add_parser("change", help="Add a new change to the changelog")
    change.add_argument(
        "type",
        type=str,
        choices=[ct.value for ct in ChangeType],
        help="Type of change (added, changed, fixed, removed, deprecated, security)",
    )
    change.add_argument("change", type=str, help="Description of the change")
    _ = subs.add_parser("release", help="Commit, tag last release and push")
    return parser


def main():
    parser = get_parser()
    args = parser.parse_args()
    if args.command == "sync":
        sync_changelog()
    elif args.command == "bump":
        bump(args.version)
    elif args.command == "change":
        change(ChangeType(args.type), args.change)
    elif args.command == "release":
        release()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
