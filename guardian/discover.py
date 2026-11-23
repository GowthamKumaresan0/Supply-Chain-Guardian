"""[1] Discovery agent: read package.json + package-lock.json (v2/v3) and build
the component inventory and the exact dependency edges."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

from .models import Component


@dataclass
class Inventory:
    app_name: str
    app_version: str
    manifest: dict
    components: dict[str, Component]            # key -> Component
    edges: list[tuple[str, str, str]]           # (parent_key, child_key, kind)
    unresolved: list[tuple[str, str]] = field(default_factory=list)  # (parent_key, dep_name)
    lockfile_version: int = 0
    ranges: dict[tuple[str, str], str] = field(default_factory=dict)  # (parent_key, child_key) -> requested range
    declared_in: dict[str, str] = field(default_factory=dict)         # direct dep name -> package.json section


def _name_from_key(key: str) -> str:
    # "node_modules/a/node_modules/@scope/b" -> "@scope/b"
    return key.rsplit("node_modules/", 1)[-1]


def npm_purl(name: str, version: str) -> str:
    if name.startswith("@"):
        scope, pkg = name[1:].split("/", 1)
        return f"pkg:npm/%40{quote(scope)}/{quote(pkg)}@{quote(version, safe='')}"
    return f"pkg:npm/{quote(name)}@{quote(version, safe='')}"


def _resolve(packages: dict, parent_key: str, dep: str) -> str | None:
    """Node's module resolution: look in parent's node_modules, then walk up."""
    base = parent_key
    while True:
        candidate = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
        if candidate in packages:
            return candidate
        if not base:
            return None
        idx = base.rfind("/node_modules/")
        base = base[:idx] if idx != -1 else ""


def discover(app_dir: Path) -> Inventory:
    manifest = json.loads((app_dir / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((app_dir / "package-lock.json").read_text(encoding="utf-8"))
    lv = int(lock.get("lockfileVersion", 1))
    if lv < 2 or "packages" not in lock:
        raise SystemExit("Only npm lockfile v2/v3 is supported in this prototype.")
    packages: dict = lock["packages"]

    direct_specs: dict[str, str] = {}
    declared_in: dict[str, str] = {}
    for sect in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (manifest.get(sect, {}) or {}).items():
            direct_specs[name] = spec
            declared_in.setdefault(name, sect)

    comps: dict[str, Component] = {}
    for key, meta in packages.items():
        if key == "" or meta.get("link"):
            continue
        name = meta.get("name") or _name_from_key(key)
        version = str(meta.get("version", ""))
        is_direct = key == f"node_modules/{name}" and name in direct_specs
        comps[key] = Component(
            key=key,
            name=name,
            version=version,
            purl=npm_purl(name, version),
            direct=is_direct,
            dev=bool(meta.get("dev") or meta.get("devOptional")),
            optional=bool(meta.get("optional")),
            resolved=meta.get("resolved", ""),
            integrity=meta.get("integrity", ""),
            has_install_script=bool(meta.get("hasInstallScript")),
            declared_spec=direct_specs.get(name, "") if is_direct else "",
        )

    edges: list[tuple[str, str, str]] = []
    unresolved: list[tuple[str, str]] = []
    ranges: dict[tuple[str, str], str] = {}
    for key, meta in packages.items():
        if meta.get("link"):
            continue
        for kind in ("dependencies", "optionalDependencies", "peerDependencies", "devDependencies"):
            if kind == "devDependencies" and key != "":
                continue  # dev deps of dependencies are never installed
            for dep, rng in (meta.get(kind) or {}).items():
                child = _resolve(packages, key, dep)
                if child and child in comps:
                    edges.append((key, child, kind))
                    ranges.setdefault((key, child), str(rng))
                elif kind in ("dependencies",):
                    unresolved.append((key, dep))

    return Inventory(
        app_name=manifest.get("name", app_dir.name),
        app_version=manifest.get("version", "0.0.0"),
        manifest=manifest,
        components=comps,
        edges=edges,
        unresolved=unresolved,
        lockfile_version=lv,
        ranges=ranges,
        declared_in=declared_in,
    )
