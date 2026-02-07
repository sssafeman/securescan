"""Dependency extraction from package manifests.

Reads requirements.txt, setup.py, package.json, etc. to identify
third-party dependencies for vulnerability cross-referencing.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class Dependency:
    """A single dependency declaration."""

    name: str
    version_spec: str | None = None
    source_file: str = ""


@dataclass
class DependencyManifest:
    """All dependencies found in a repository."""

    python_deps: list[Dependency] = field(default_factory=list)
    js_deps: list[Dependency] = field(default_factory=list)
    manifest_files_found: list[str] = field(default_factory=list)

    @property
    def all_deps(self) -> list[Dependency]:
        return self.python_deps + self.js_deps


_PIP_LINE_RE = re.compile(
    r"^([A-Za-z0-9_.-]+)\s*(?:([><=!~]+.*))?",
)


def _parse_requirements_txt(path: Path) -> list[Dependency]:
    """Parse a requirements.txt file."""

    deps: list[Dependency] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            match = _PIP_LINE_RE.match(line)
            if match:
                deps.append(
                    Dependency(
                        name=match.group(1),
                        version_spec=match.group(2),
                        source_file=path.name,
                    )
                )
    except OSError:
        pass
    return deps


def _parse_package_json(path: Path) -> list[Dependency]:
    """Parse a package.json file."""

    deps: list[Dependency] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        for section in ("dependencies", "devDependencies"):
            for name, version in data.get(section, {}).items():
                deps.append(
                    Dependency(
                        name=name,
                        version_spec=version,
                        source_file=path.name,
                    )
                )
    except (OSError, json.JSONDecodeError):
        pass
    return deps


def extract_dependencies(repo_root: Path) -> DependencyManifest:
    """Extract all dependency declarations from a repository.

    Looks for:
    - requirements.txt, requirements/*.txt
    - setup.py, setup.cfg, pyproject.toml (basic parsing)
    - package.json
    """

    manifest = DependencyManifest()

    for pattern in ("requirements.txt", "requirements/*.txt", "requirements-*.txt", "req*.txt"):
        for req_file in repo_root.glob(pattern):
            deps = _parse_requirements_txt(req_file)
            manifest.python_deps.extend(deps)
            if deps:
                manifest.manifest_files_found.append(str(req_file.relative_to(repo_root)))

    pyproject = repo_root / "pyproject.toml"
    if pyproject.exists():
        manifest.manifest_files_found.append("pyproject.toml")
        try:
            content = pyproject.read_text(encoding="utf-8")
            in_deps = False
            for line in content.splitlines():
                if line.strip() == "dependencies = [":
                    in_deps = True
                    continue
                if in_deps:
                    if line.strip() == "]":
                        break
                    pkg_match = re.match(r'\s*"([A-Za-z0-9_.-]+)', line)
                    if pkg_match:
                        manifest.python_deps.append(
                            Dependency(
                                name=pkg_match.group(1),
                                source_file="pyproject.toml",
                            )
                        )
        except OSError:
            pass

    pkg_json = repo_root / "package.json"
    if pkg_json.exists():
        deps = _parse_package_json(pkg_json)
        manifest.js_deps.extend(deps)
        if deps:
            manifest.manifest_files_found.append("package.json")

    logger.info(
        f"Dependencies: {len(manifest.python_deps)} Python, "
        f"{len(manifest.js_deps)} JS "
        f"(from {len(manifest.manifest_files_found)} manifest files)"
    )

    return manifest
