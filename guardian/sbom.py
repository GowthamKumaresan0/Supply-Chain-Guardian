"""[2] SBOM: emit CycloneDX 1.5 JSON (components + dependency relationships).
Optionally cross-check component count with Syft."""
from __future__ import annotations

import base64
import json
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .discover import Inventory, npm_purl

_HASH_ALG = {"sha512": "SHA-512", "sha384": "SHA-384", "sha256": "SHA-256", "sha1": "SHA-1"}


def _integrity_to_hashes(integrity: str) -> list[dict]:
    out = []
    for part in (integrity or "").split():
        alg, _, b64 = part.partition("-")
        if alg in _HASH_ALG and b64:
            try:
                out.append({"alg": _HASH_ALG[alg], "content": base64.b64decode(b64).hex()})
            except Exception:
                pass
    return out


def build_cyclonedx(inv: Inventory) -> dict:
    root_ref = npm_purl(inv.app_name, inv.app_version)
    ref = {k: f"{c.purl}#{k}" for k, c in inv.components.items()}  # unique even for duplicate versions
    ref[""] = root_ref

    components = []
    for k, c in inv.components.items():
        comp = {
            "type": "library",
            "bom-ref": ref[k],
            "name": c.name,
            "version": c.version,
            "purl": c.purl,
            "scope": "optional" if c.dev else "required",
            "properties": [
                {"name": "guardian:lockPath", "value": k},
                {"name": "guardian:direct", "value": str(c.direct).lower()},
                {"name": "guardian:dev", "value": str(c.dev).lower()},
                {"name": "guardian:hasInstallScript", "value": str(c.has_install_script).lower()},
            ],
        }
        hashes = _integrity_to_hashes(c.integrity)
        if hashes:
            comp["hashes"] = hashes
        if c.resolved:
            comp["externalReferences"] = [{"type": "distribution", "url": c.resolved}]
        components.append(comp)

    deps: dict[str, list[str]] = {r: [] for r in ref.values()}
    for parent, child, _kind in inv.edges:
        deps[ref[parent]].append(ref[child])

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": {"components": [{"type": "application", "name": "supply-chain-guardian",
                                      "version": __version__}]},
            "component": {"type": "application", "bom-ref": root_ref, "name": inv.app_name,
                          "version": inv.app_version, "purl": root_ref},
        },
        "components": components,
        "dependencies": [{"ref": r, "dependsOn": sorted(set(d))} for r, d in deps.items()],
    }


def write_sbom(inv: Inventory, out: Path, name: str = "sbom.cdx.json") -> Path:
    path = out / name
    path.write_text(json.dumps(build_cyclonedx(inv), indent=2), encoding="utf-8")
    return path


def syft_crosscheck(app_dir: Path, out: Path) -> dict:
    """Run Syft (if installed) as an independent SBOM generator and compare counts."""
    exe = shutil.which("syft")
    if not exe:
        return {"available": False}
    dest = out / "sbom.syft.cdx.json"
    try:
        subprocess.run([exe, f"dir:{app_dir}", "-q", "-o", f"cyclonedx-json={dest}"],
                       check=True, capture_output=True, timeout=300)
        data = json.loads(dest.read_text(encoding="utf-8"))
        names = {(c.get("name"), c.get("version")) for c in data.get("components", [])
                 if c.get("purl", "").startswith("pkg:npm/")}
        return {"available": True, "file": dest.name, "npm_components": len(names)}
    except Exception as e:  # never fail the scan because of the cross-check
        return {"available": True, "error": str(e)[:300]}
